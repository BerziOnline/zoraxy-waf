package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zoraxy-waf-plugin/internal/engine"
)

func sampleRequest() *engine.Request {
	return &engine.Request{
		Method: "POST", RawURI: "/login?token=tok-SECRET-123&next=%2Fhome&flag", Proto: "HTTP/1.1",
		Host: "Shop.Example:443", RouteID: "shop.example", ClientIP: "203.0.113.5",
		Header: map[string][]string{
			"Authorization": {"Bearer bearer-SECRET-456"},
			"Cookie":        {"sid=cookie-SECRET-789; theme=dark"},
			"User-Agent":    {"curl/8"},
			"Content-Type":  {"application/x-www-form-urlencoded"},
			"X-Api-Key":     {"apikey-SECRET-000"},
		},
		Body: []byte("user=alice&password=pw-SECRET-abc"),
	}
}

func TestNewEventRedactsSecrets(t *testing.T) {
	req := sampleRequest()
	matches := []engine.Match{{RuleID: 942100, Message: "SQL Injection found within ARGS:password: pw-SECRET-abc", Targets: []string{"ARGS_POST:password"}}}
	ev := FromRequest(req, matches)
	b, _ := json.Marshal(ev)
	s := string(b)
	for _, secret := range []string{"tok-SECRET-123", "bearer-SECRET-456", "cookie-SECRET-789", "pw-SECRET-abc", "apikey-SECRET-000"} {
		if strings.Contains(s, secret) {
			t.Errorf("event leaks %s: %s", secret, s)
		}
	}
	if ev.Path != "/login" || ev.Query != "token=[redacted]&next=[redacted]&flag" {
		t.Fatalf("path/query redaction: %q %q", ev.Path, ev.Query)
	}
	if ev.Host != "shop.example" || ev.RouteID != "shop.example" || ev.ClientIP != "203.0.113.5" || ev.UserAgent != "curl/8" {
		t.Fatalf("metadata: %+v", ev)
	}
	if !strings.Contains(ev.Matches[0].Message, "[redacted]") {
		t.Fatalf("message not scrubbed: %q", ev.Matches[0].Message)
	}
	found := false
	for _, h := range ev.HeaderNames {
		if h == "Authorization" {
			found = true
		}
	}
	if !found {
		t.Fatal("header names should be kept (values dropped)")
	}
}

func TestRingNewestFirstBoundedAndFilters(t *testing.T) {
	s := newStore(t.TempDir(), 100, 1<<20, 2, 16, true)
	defer s.Close()
	for i := 0; i < 150; i++ {
		ev := Event{ID: fmt.Sprintf("e%03d", i), Time: time.Unix(int64(i), 0), Host: "a.example", Action: ActionAllowed, ClientIP: "198.51.100.1", Path: "/x"}
		if i%10 == 0 {
			ev.Host, ev.Action, ev.Matches = "b.example", ActionBlocked, []engine.Match{{RuleID: 942100, Message: "SQLi"}}
		}
		s.Add(ev)
	}
	all := s.List(Filter{})
	if len(all) != 100 || all[0].ID != "e149" {
		t.Fatalf("ring size/order: %d %s", len(all), all[0].ID)
	}
	if _, ok := s.Get("e010"); ok {
		t.Fatal("evicted event still retrievable")
	}
	if _, ok := s.Get("e140"); !ok {
		t.Fatal("recent event missing")
	}
	b := s.List(Filter{Host: "b.example", Action: ActionBlocked, RuleID: 942100})
	if len(b) != 10 { // events 50..149 remain; every 10th is blocked
		t.Fatalf("filter returned %d", len(b))
	}
	if len(s.List(Filter{Text: "sqli"})) != 10 || len(s.List(Filter{ClientIP: "198.51.100.1", Limit: 7})) != 7 {
		t.Fatal("text/ip/limit filter")
	}
	if len(s.List(Filter{Since: time.Unix(145, 0)})) != 5 {
		t.Fatal("since filter")
	}
}

func TestJSONLRotationCapAndMode(t *testing.T) {
	dir := t.TempDir()
	s := newStore(dir, 100, 2048, 2, 1024, true)
	for i := 0; i < 200; i++ {
		s.Add(Event{ID: fmt.Sprintf("e%03d", i), Host: "a.example", Action: ActionWouldBlock, Path: "/" + strings.Repeat("p", 50)})
	}
	s.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "events.jsonl*"))
	if len(files) == 0 || len(files) > 3 {
		t.Fatalf("expected active + at most 2 rotated files, got %v", files)
	}
	var total int64
	for _, f := range files {
		st, _ := os.Stat(f)
		if st.Size() > 2048 {
			t.Errorf("%s exceeds cap: %d", f, st.Size())
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, st.Mode())
		}
		total += st.Size()
		fh, _ := os.Open(f)
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			var ev Event
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil || ev.Version != 1 {
				t.Errorf("invalid JSONL line in %s: %s", f, sc.Text())
			}
		}
		fh.Close()
	}
	if total > 3*2048 {
		t.Fatalf("disk usage not bounded: %d", total)
	}
	st := s.Stats()
	if st.Written == 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestQueueFullCountsDrops(t *testing.T) {
	s := newStore(t.TempDir(), 100, 1<<20, 1, 2, false) // writer not started
	for i := 0; i < 10; i++ {
		s.Add(Event{ID: fmt.Sprint(i)})
	}
	if st := s.Stats(); st.Dropped != 8 {
		t.Fatalf("dropped = %d, want 8", st.Dropped)
	}
	if len(s.List(Filter{})) != 10 {
		t.Fatal("ring must still hold events when the file queue is full")
	}
}

func TestUnwritableDirectoryCountsErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "events")
	os.WriteFile(blocker, []byte("x"), 0o600) // a file where the directory should be
	s := newStore(blocker, 100, 1<<20, 1, 16, true)
	s.Add(Event{ID: "1"})
	s.Close()
	if st := s.Stats(); st.WriteErrors == 0 && st.Dropped == 0 {
		t.Fatalf("write failure not visible: %+v", st)
	}
}

func TestExportJSONL(t *testing.T) {
	s := newStore(t.TempDir(), 100, 1<<20, 1, 16, true)
	defer s.Close()
	s.Add(Event{ID: "a", Host: "a.example"})
	s.Add(Event{ID: "b", Host: "b.example"})
	var buf bytes.Buffer
	if err := s.Export(&buf, Filter{Host: "b.example"}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), "\n") != 1 || !strings.Contains(buf.String(), `"id":"b"`) {
		t.Fatalf("export %q", buf.String())
	}
}

func TestSuggestSmallestExceptions(t *testing.T) {
	ev := Event{ID: "x", Host: "shop.example", RouteID: "shop.example", Method: "GET", Path: "/search",
		Matches: []engine.Match{
			{RuleID: 942100, Targets: []string{"ARGS_GET:q"}},
			{RuleID: 920350, Targets: []string{"REQUEST_HEADERS:Host"}},
			{RuleID: 949110, Targets: []string{"TX:blocking_inbound_anomaly_score"}},
			{RuleID: 980170},
		}}
	got := Suggest(ev)
	if len(got) != 2 {
		t.Fatalf("suggestions %+v", got)
	}
	if got[0].RuleID != 942100 || got[0].Argument != "q" || got[0].Host != "shop.example" || got[0].Method != "GET" || got[0].Path != "/search" {
		t.Fatalf("argument-scoped suggestion %+v", got[0])
	}
	if got[1].RuleID != 920350 || got[1].Argument != "" {
		t.Fatalf("whole-rule suggestion %+v", got[1])
	}
	ev.RouteID = ""
	if Suggest(ev)[0].Host != "shop.example" {
		t.Fatal("host fallback")
	}
}

func TestNewIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewID()
		if seen[id] || len(id) < 16 {
			t.Fatalf("bad id %q", id)
		}
		seen[id] = true
	}
}
