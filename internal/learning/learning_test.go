package learning

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/events"
)

func TestPatternGroupsIDsOnly(t *testing.T) {
	for in, want := range map[string]string{
		"/api/v4/users/me/preferences":                     "/api/v4/users/me/preferences",
		"/api/v4/users/8f3k2m9q1x7d4b6pq1x7d4b6pq/patch":   "/api/v4/users/*/patch",
		"/api/assets/0b7c3c2e-6f4b-4a8e-9d1c-2f0e5b7a9c11": "/api/assets/*",
		"/posts/12345/comments":                            "/posts/*/comments",
		"/item/ab12cd34":                                   "/item/*",
		"/plugins/playbooks/api/v0/query":                  "/plugins/playbooks/api/v0/query",
		"/static/IMG_20261031_123456.jpg":                  "/static/IMG_20261031_123456.jpg",
		"/v2":                                              "/v2",
		"/":                                                "/",
	} {
		if got := Pattern(in); got != want {
			t.Errorf("Pattern(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWithLoginUsesHeaderNamesOnly(t *testing.T) {
	yes := [][]string{{"Cookie"}, {"authorization"}, {"X-Immich-User-Token"}, {"X-Api-Key"}, {"X-Session-Id"}}
	for _, h := range yes {
		if !WithLogin(h) {
			t.Errorf("%v must count as login", h)
		}
	}
	if WithLogin([]string{"User-Agent", "Accept", "Content-Type", "X-Forwarded-For"}) {
		t.Error("plain browser headers counted as login")
	}
}

func ev(path, ip string, login bool, rule int) events.Event {
	e := events.Event{ID: events.NewID(), Time: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC), Host: "mm.example", Method: "PATCH", Path: path, ClientIP: ip, HeaderNames: []string{"User-Agent"},
		Matches: []engine.Match{{RuleID: rule, Message: "Method is not allowed by policy"}, {RuleID: 949110, Message: "Inbound Anomaly Score Exceeded"}}}
	if login {
		e.HeaderNames = append(e.HeaderNames, "Cookie")
	}
	return e
}

func TestRecordGroupsCountsAndPersists(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir)
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	s.Observe("mm.example", now)
	s.Observe("mm.example", now.Add(time.Hour))
	s.Record("mm.example", ev("/api/v2/boards/8f3k2m9q1x7d4b6p/blocks", "198.51.100.1", true, 911100), true)
	s.Record("mm.example", ev("/api/v2/boards/zz99zz99zz99zz99/blocks", "198.51.100.2", false, 911100), false)
	s.Record("mm.example", ev("/api/v2/boards/zz99zz99zz99zz99/blocks", "198.51.100.2", false, 911100), false)
	h := s.Snapshot()["mm.example"]
	if !h.Since.Equal(now) || h.Requests != 2 || len(h.Findings) != 1 {
		t.Fatalf("host record: %+v", h)
	}
	f := h.Findings[SortedKeys(h)[0]]
	if f.Count != 3 || f.WithLogin != 1 || len(f.Clients) != 2 || f.Path != "/api/v2/boards/*/blocks" || len(f.Rules) != 1 || !f.HasRule(911100) {
		t.Fatalf("finding: %+v", f)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "learning.json"))
	for _, secret := range []string{"198.51.100.1", "Cookie"} {
		if contains := string(b); len(contains) > 0 && containsStr(contains, secret) {
			t.Fatalf("learning record stores %q", secret)
		}
	}
	again := Open(dir).Snapshot()["mm.example"]
	if again.Requests != 2 || len(again.Findings) != 1 {
		t.Fatalf("reload: %+v", again)
	}
	// Damaged file: kept aside, learning starts over, reason reported.
	os.WriteFile(filepath.Join(dir, "learning.json"), []byte("{broken"), 0o600)
	d := Open(dir)
	if d.LoadError() == "" || len(d.Snapshot()) != 0 {
		t.Fatal("damaged record not reported")
	}
	if _, err := os.Stat(filepath.Join(dir, "learning.json.broken")); err != nil {
		t.Fatal("damaged record not kept")
	}
}

func path(i int) string { return "/p" + string(rune('a'+i%26)) + string(rune('a'+i/26)) }

// At the cap, scanner findings make room for login findings; a login finding
// that cannot be kept is counted, so the host cannot graduate on lost evidence.
func TestFindingsAreCappedPerHostWithoutLosingLoginEvidence(t *testing.T) {
	s := Open(t.TempDir())
	for i := 0; i < maxFindingsPerHost+5; i++ {
		s.Record("x.example", ev(path(i), "", false, 941100), false)
	}
	h := s.Snapshot()["x.example"]
	if len(h.Findings) != maxFindingsPerHost || h.Dropped != 5 || h.DroppedLogin != 0 {
		t.Fatalf("cap: %d findings, %d dropped, %d login dropped", len(h.Findings), h.Dropped, h.DroppedLogin)
	}
	s.Record("x.example", ev("/login-finding", "", true, 941100), true)
	h = s.Snapshot()["x.example"]
	if f := h.Findings[FindingKey("PATCH", "/login-finding")]; f == nil || len(h.Findings) != maxFindingsPerHost {
		t.Fatal("login finding must evict a scanner finding")
	}
	full := Open(t.TempDir())
	for i := 0; i < maxFindingsPerHost; i++ {
		full.Record("y.example", ev(path(i), "", true, 941100), true)
	}
	full.Record("y.example", ev("/one-more", "", true, 941100), true)
	if h := full.Snapshot()["y.example"]; h.DroppedLogin != 1 {
		t.Fatalf("lost login finding not counted: %+v", h.DroppedLogin)
	}
	if !WithLoginHeader(map[string][]string{"A": nil, "X-Auth-Token": {"x"}}) || WithLoginHeader(map[string][]string{"Accept": nil}) {
		t.Fatal("WithLoginHeader")
	}
}

func TestDismissAndReset(t *testing.T) {
	s := Open(t.TempDir())
	s.Record("a.example", ev("/x", "", true, 941100), true)
	k := SortedKeys(s.Snapshot()["a.example"])[0]
	if err := s.Dismiss("a.example", k, true); err != nil || !s.Snapshot()["a.example"].Findings[k].Dismissed {
		t.Fatal("dismiss failed")
	}
	s.Reset("a.example")
	if _, ok := s.Snapshot()["a.example"]; ok {
		t.Fatal("reset kept the host")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestOpenRemovesInterruptedWrites(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir)
	s.Observe("chat.example.test", time.Now())
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "learning.json.1874195705.tmp")
	keep := filepath.Join(dir, "learning.json.broken")
	for _, f := range []string{stale, keep} {
		if err := os.WriteFile(f, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	again := Open(dir)
	if again.LoadError() != "" || len(again.Hosts()) != 1 {
		t.Fatalf("record lost: %q %d", again.LoadError(), len(again.Hosts()))
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("interrupted temp file kept")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("unrelated file removed")
	}
}
