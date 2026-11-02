package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/wire"
)

// callSniff drives the dynamic capture sniff protocol the way Zoraxy does
// for a plugin that declared dynamic_capture_sniff_body_kb: one call, with
// the body prefix (at most the configured size) attached when there is a body.
func callSniff(t *testing.T, s *Service, p wire.InspectPayload) (code int, hdr http.Header) {
	t.Helper()
	limit := s.Current().SniffBodyKB() * 1024
	if len(p.Body) > 0 {
		p.Header["Content-Length"] = []string{strconv.Itoa(len(p.Body))}
		p.BodyIncluded = true
		if len(p.Body) > limit {
			p.Body = p.Body[:limit]
			p.BodyTruncated = true
		}
	}
	return postSniff(t, s, p)
}

func postSniff(t *testing.T, s *Service, p wire.InspectPayload) (int, http.Header) {
	t.Helper()
	b, _ := json.Marshal(p)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18482/sniff/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.IPCHandler().ServeHTTP(rec, req)
	return rec.Code, rec.Header()
}

func TestSniffOffModeSkips(t *testing.T) {
	s := newSvc(t, Options{})
	code, _ := callSniff(t, s, payload("POST", "/login", "user=admin' OR 1=1--"))
	if code != wire.SniffSkip {
		t.Fatalf("off mode must skip, got %d", code)
	}
	if st := s.Stats(); st.Skipped != 1 || st.Inspected != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestSniffGetIsDecided(t *testing.T) {
	s := newSvc(t, Options{})
	setMode(t, s, config.ModeBlock)
	code, hdr := callSniff(t, s, payload("GET", "/?q="+q("<script>alert(1)</script>"), ""))
	if code != wire.SniffDeny {
		t.Fatalf("GET attack: want 286, got %d", code)
	}
	if hdr.Get("X-Zoraxy-Deny-Status") != "403" || !strings.HasPrefix(hdr.Get("X-Zoraxy-Deny-Reason"), "waf-941") {
		t.Fatalf("deny headers must name the XSS rule for Zoraxy's log: %v", hdr)
	}
	if code, _ = callSniff(t, s, payload("GET", "/search?q="+q("garden chairs"), "")); code != wire.SniffSkip {
		t.Fatalf("benign GET: want 501, got %d", code)
	}
}

func TestSniffPostIsDecidedWithTheBodyInOneCall(t *testing.T) {
	s := newSvc(t, Options{})
	setMode(t, s, config.ModeBlock)
	code, hdr := callSniff(t, s, payload("POST", "/login", "user=admin' OR 1=1--"))
	if code != wire.SniffDeny || hdr.Get("X-Zoraxy-Deny-Status") != "403" {
		t.Fatalf("POST attack: want 286/403, got %d %v", code, hdr)
	}
	if code, _ = callSniff(t, s, payload("POST", "/login", "username=alice&password="+q("correct horse battery staple"))); code != wire.SniffSkip {
		t.Fatalf("benign POST: want 501, got %d", code)
	}
	if st := s.Stats(); st.Inspected != 2 || st.Blocked != 1 || st.Allowed != 1 {
		t.Fatalf("stats %+v", st)
	}
	if h := s.Health(); h.BodiesMissing != 0 || h.ZoraxyBodyKB != 0 {
		t.Fatalf("bodies were delivered, health %+v", h)
	}
}

func TestSniffBodySizeAskedFromZoraxyIsTheLargestHostSetting(t *testing.T) {
	c := config.Default()
	if c.SniffBodyKB() != 64 {
		t.Fatalf("default: want 64, got %d", c.SniffBodyKB())
	}
	c.Hosts = map[string]config.HostOverride{"a.example": {Mode: config.ModeInherit, MaxBodyKB: 256}, "b.example": {Mode: config.ModeInherit, MaxBodyKB: 8}}
	if c.SniffBodyKB() != 256 {
		t.Fatalf("want the largest host setting 256, got %d", c.SniffBodyKB())
	}
}

func TestSniffReportsWhenZoraxyDeliversLessBodyThanSet(t *testing.T) {
	s := newSvc(t, Options{})
	setMode(t, s, config.ModeBlock, func(c *config.Config) { c.MaxBodyKB = 128 })
	// A Zoraxy without the body field sends headers only.
	p := payload("POST", "/login", "")
	p.Header["Content-Length"] = []string{"20"}
	p.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	if code, _ := postSniff(t, s, p); code != wire.SniffSkip {
		t.Fatalf("headers-only POST: want 501, got %d", code)
	}
	if s.Health().BodiesMissing != 1 {
		t.Fatalf("missing body not counted: %+v", s.Health())
	}
	// A Zoraxy that read 64 KiB at its start, before the change to 128.
	p = payload("POST", "/upload", string(bytes.Repeat([]byte("a"), 64*1024)))
	p.Header["Content-Type"] = []string{"application/octet-stream"}
	p.BodyIncluded, p.BodyTruncated = true, true
	postSniff(t, s, p)
	if s.Health().ZoraxyBodyKB != 64 {
		t.Fatalf("want ZoraxyBodyKB 64, got %+v", s.Health())
	}
	// After a Zoraxy restart the full 128 KiB arrive and the note clears.
	p.Body = bytes.Repeat([]byte("a"), 128*1024)
	postSniff(t, s, p)
	if s.Health().ZoraxyBodyKB != 0 {
		t.Fatalf("note must clear when the set size arrives, got %+v", s.Health())
	}
}

func TestSniffReportModeNeverDenies(t *testing.T) {
	s := newSvc(t, Options{})
	setMode(t, s, config.ModeReport)
	code, _ := callSniff(t, s, payload("POST", "/login", "user=admin' OR 1=1--"))
	if code != wire.SniffSkip {
		t.Fatalf("report mode must skip, got %d", code)
	}
	if st := s.Stats(); st.WouldBlock != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestSniffEngineFailureFollowsFailurePolicy(t *testing.T) {
	fe := &fakeEngine{err: errors.New("boom")}
	s := newSvc(t, Options{Build: func(config.Config) (engine.Engine, error) { return fe, nil }})
	setMode(t, s, config.ModeBlock)
	if code, _ := callSniff(t, s, payload("GET", "/", "")); code != wire.SniffSkip {
		t.Fatalf("fail-open default: want 501, got %d", code)
	}
	setMode(t, s, config.ModeBlock, func(c *config.Config) { c.FailClosed = true })
	code, hdr := callSniff(t, s, payload("GET", "/", ""))
	if code != wire.SniffDeny || hdr.Get("X-Zoraxy-Deny-Status") != "503" {
		t.Fatalf("fail-closed: want 286/503, got %d %v", code, hdr)
	}
	// Report and learning never block, not even on inspection failure.
	for _, mode := range []string{config.ModeReport, config.ModeLearn} {
		setMode(t, s, mode, func(c *config.Config) { c.FailClosed = true })
		if code, _ := callSniff(t, s, payload("GET", "/", "")); code != wire.SniffSkip {
			t.Fatalf("%s with fail-closed must still skip on engine failure, got %d", mode, code)
		}
	}
}

func TestSniffBadPayloadAndCaptureIngress(t *testing.T) {
	s := newSvc(t, Options{})
	do := func(method, target, body string) int {
		req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		rec := httptest.NewRecorder()
		s.IPCHandler().ServeHTTP(rec, req)
		return rec.Code
	}
	if c := do("GET", "http://127.0.0.1:1/sniff/", ""); c != http.StatusMethodNotAllowed {
		t.Errorf("GET /sniff/ = %d", c)
	}
	if c := do("POST", "http://127.0.0.1:1/sniff/", "{nope"); c != http.StatusBadRequest {
		t.Errorf("bad JSON = %d", c)
	}
	if c := do("GET", "http://127.0.0.1:1/capture/anything", ""); c != http.StatusNotFound {
		t.Errorf("capture ingress must not serve traffic, got %d", c)
	}
}

func TestDeclaresBody(t *testing.T) {
	cases := []struct {
		h    map[string][]string
		want bool
	}{
		{map[string][]string{}, false},
		{map[string][]string{"Content-Length": {"0"}}, false},
		{map[string][]string{"Content-Length": {"12"}}, true},
		{map[string][]string{"content-length": {" 7 "}}, true},
		{map[string][]string{"Transfer-Encoding": {"chunked"}}, true},
		{map[string][]string{"Content-Type": {"application/json"}}, false},
	}
	for _, c := range cases {
		if got := declaresBody(c.h); got != c.want {
			t.Errorf("declaresBody(%v) = %v, want %v", c.h, got, c.want)
		}
	}
}

func TestSniffBurstBeyondCapacityIsQueuedNotSkipped(t *testing.T) {
	s := newSvc(t, Options{})
	setMode(t, s, config.ModeBlock, func(c *config.Config) { c.MaxConcurrent = 2 })
	const n = 24
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() {
			code, _ := callSniff(t, s, payload("POST", "/api/assets", "field="+strconv.Itoa(len(codes))+"&data=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))
			codes <- code
		}()
	}
	for i := 0; i < n; i++ {
		if c := <-codes; c != wire.SniffSkip {
			t.Fatalf("burst request %d: want 501 (inspected, clean), got %d", i, c)
		}
	}
	if st := s.Stats(); st.Saturated != 0 || st.Inspected != n {
		t.Fatalf("a burst of %d must be inspected completely with 2 slots, stats %+v", n, st)
	}
}

func TestDenyReasonNamesTheDetectingRule(t *testing.T) {
	d := engine.Decision{Matches: []engine.Match{{RuleID: 920350, Severity: "warning"}, {RuleID: 942100, Severity: "critical"}, {RuleID: 942190, Severity: "critical"}, {RuleID: 949110, Severity: "emergency"}, {RuleID: 980170}}}
	if got := denyReason(d); got != "waf-942100" {
		t.Fatalf("want the first critical detection waf-942100, got %q", got)
	}
	if got := denyReason(engine.Decision{Matches: []engine.Match{{RuleID: 949110}}}); got != "waf" {
		t.Fatalf("score rule only: want waf, got %q", got)
	}
}

func TestSniffMissingBodyFollowsFailClosedOnBlockingHosts(t *testing.T) {
	s := newSvc(t, Options{})
	p := payload("POST", "/login", "")
	p.Header["Content-Length"] = []string{"20"}
	p.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	setMode(t, s, config.ModeBlock)
	if code, _ := postSniff(t, s, p); code != wire.SniffSkip {
		t.Fatalf("fail-open default: a request without its body is inspected by headers, got %d", code)
	}
	setMode(t, s, config.ModeBlock, func(c *config.Config) { c.FailClosed = true })
	if code, hdr := postSniff(t, s, p); code != wire.SniffDeny || hdr.Get("X-Zoraxy-Deny-Status") != "503" || hdr.Get("X-Zoraxy-Deny-Reason") != "waf-body-missing" {
		t.Fatalf("fail-closed blocking host must reject a request whose body did not arrive, got %d %v", code, hdr)
	}
	setMode(t, s, config.ModeLearn, func(c *config.Config) { c.FailClosed = true })
	if code, _ := postSniff(t, s, p); code != wire.SniffSkip {
		t.Fatalf("learning never blocks, got %d", code)
	}
	// A body that did arrive is never affected.
	p.Body, p.BodyIncluded = []byte("user=alice&city=Berlin"), true
	setMode(t, s, config.ModeBlock, func(c *config.Config) { c.FailClosed = true })
	if code, _ := postSniff(t, s, p); code != wire.SniffSkip {
		t.Fatalf("delivered body: want 501, got %d", code)
	}
}

// Zoraxy cuts all bodies at one size. A host with a small limit receiving a
// cut body must not clear the note raised for a host that wants more.
func TestSniffBodySizeNoteAcrossHosts(t *testing.T) {
	s := newSvc(t, Options{})
	setMode(t, s, config.ModeReport, func(c *config.Config) {
		c.MaxBodyKB = 8
		c.Hosts = map[string]config.HostOverride{"files.example": {Mode: config.ModeInherit, MaxBodyKB: 512}}
	})
	cut := func(host string, kb int) {
		p := payload("POST", "/upload", string(bytes.Repeat([]byte("a"), kb*1024)))
		p.Host, p.Hostname, p.RouteID = host, host, host
		p.Header["Content-Type"] = []string{"application/octet-stream"}
		p.BodyIncluded, p.BodyTruncated = true, true
		postSniff(t, s, p)
	}
	cut("files.example", 64) // Zoraxy still sends 64 KiB
	if s.Health().ZoraxyBodyKB != 64 {
		t.Fatalf("note expected, got %+v", s.Health())
	}
	cut("shop.example", 64) // 8 KiB host: a cut 64 KiB body says nothing new
	if s.Health().ZoraxyBodyKB != 64 {
		t.Fatalf("a small-limit host cleared the note: %+v", s.Health())
	}
	cut("files.example", 512) // after a Zoraxy restart
	if s.Health().ZoraxyBodyKB != 0 {
		t.Fatalf("note must clear when the set size arrives: %+v", s.Health())
	}
	// A delivered body also clears the missing-body counter.
	p := payload("POST", "/login", "")
	p.Header["Content-Length"] = []string{"20"}
	p.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	postSniff(t, s, p)
	if s.Health().BodiesMissing != 1 {
		t.Fatal("missing body not counted")
	}
	cut("shop.example", 8)
	if s.Health().BodiesMissing != 0 {
		t.Fatal("a delivered body must clear the missing-body note")
	}
}
