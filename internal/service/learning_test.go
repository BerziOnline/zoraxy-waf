package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/learning"
	"zoraxy-waf-plugin/internal/wire"
	"zoraxy-waf-plugin/internal/zoraxy"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }
func newClock() *clock               { return &clock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)} }
func withLogin() payloadOpt {
	return func(p *wire.InspectPayload) { p.Header["Cookie"] = []string{"session=x"} }
}
func withJSON(p *wire.InspectPayload) { p.Header["Content-Type"] = []string{"application/json"} }
func patch(host, path string, opts ...payloadOpt) wire.InspectPayload {
	o := append([]payloadOpt{withHost(host, ""), withJSON}, opts...)
	return payload("PATCH", path, `{"title":"Shopping list"}`, o...)
}

// Methods are per host: allowing PATCH on one app never opens it elsewhere,
// and the CRS default stays GET HEAD POST OPTIONS.
func TestMethodsAllowedPerHostOnly(t *testing.T) {
	s := newSvc(t, Options{MaintenanceEvery: -1})
	setMode(t, s, config.ModeBlock, func(c *config.Config) {
		c.Hosts["mm.example"] = config.HostOverride{Mode: config.ModeInherit, Methods: []string{"PUT", "PATCH", "DELETE"}}
	})
	if r := callInspect(t, s, patch("mm.example", "/api/v2/boards/b1/blocks/c2")); r.result.Action != "allow" || r.result.EventID != "" {
		t.Fatalf("PATCH on the app host must pass without event: %+v", r)
	}
	r := callInspect(t, s, patch("shop.example", "/api/v2/boards/b1/blocks/c2"))
	if r.result.Action != "deny" {
		t.Fatalf("PATCH on a host without the method must still be blocked: %+v", r)
	}
	ev, _ := s.Events().Get(r.result.EventID)
	method := false
	for _, m := range ev.Matches {
		method = method || m.RuleID == config.MethodRuleID
	}
	if !method {
		t.Fatalf("block must come from the CRS method rule: %+v", ev.Matches)
	}
	// TRACE is never allowed per host, the CRS default methods need no entry.
	for _, bad := range [][]string{{"TRACE"}, {"GET"}, {"patch"}, {"PATCH", "PATCH"}} {
		if _, err := s.Apply(func(c *config.Config) error {
			c.Hosts["mm.example"] = config.HostOverride{Mode: config.ModeInherit, Methods: bad}
			return nil
		}); err == nil {
			t.Fatalf("methods %v must be rejected", bad)
		}
	}
	// Allowing the method does not switch off the other rules.
	attack := payload("PATCH", "/api/x", `{"title":"1' OR 1=1-- -"}`, withHost("mm.example", ""), withJSON)
	if r := callInspect(t, s, attack); r.result.Action != "deny" {
		t.Fatalf("SQL injection in an allowed PATCH must be blocked: %+v", r)
	}
}

func learningService(t *testing.T, days int) (*Service, *clock) {
	t.Helper()
	ck := newClock()
	s := newSvc(t, Options{Now: ck.Now, MaintenanceEvery: -1})
	if _, err := s.Activate(config.ModeLearn, days, false); err != nil {
		t.Fatal(err)
	}
	return s, ck
}

func find(s *Service, host string) (HostStatus, bool) {
	rows, _ := s.HostStatuses(0)
	for _, r := range rows {
		if r.Host == host {
			return r, true
		}
	}
	return HostStatus{}, false
}

func status(t *testing.T, s *Service, host string) HostStatus {
	t.Helper()
	r, ok := find(s, host)
	if !ok {
		t.Fatalf("host %s not listed", host)
	}
	return r
}

func TestLearningHostBlocksAfterPeriodWithoutOpenFindings(t *testing.T) {
	s, ck := learningService(t, 7)
	if _, ok := find(s, "shop.example"); ok {
		t.Fatal("a host without request, route or override must not be listed")
	}
	clean := payload("GET", "/", "", withHost("shop.example", ""))
	if r := callInspect(t, s, clean); r.result.Action != "allow" {
		t.Fatal(r)
	}
	// A scanner attack (no login) is recorded, not blocked, and does not hold the host.
	if r := callInspect(t, s, payload("GET", "/?q="+q("<script>alert(1)</script>"), "", withHost("shop.example", ""))); r.result.Action != "allow" || r.result.EventID == "" {
		t.Fatalf("learning must record, not block: %+v", r)
	}
	st := status(t, s, "shop.example")
	if st.Learning == nil || st.Learning.State != "learning" || st.Learning.Day != 1 || st.Learning.Requests != 2 || st.Open != 0 {
		t.Fatalf("day 1: %+v / %+v", st, st.Learning)
	}
	if len(st.Findings) == 0 || st.Findings[0].Status != "scanner" {
		t.Fatalf("attack without login must be a scanner finding: %+v", st.Findings)
	}
	ck.Add(6 * 24 * time.Hour)
	if done := s.LearningTick(); len(done) != 0 {
		t.Fatalf("switched before the period ended: %v", done)
	}
	ck.Add(24*time.Hour + time.Minute)
	done := s.LearningTick()
	if len(done) != 1 || done[0] != "shop.example" {
		t.Fatalf("host must switch to block after 7 days: %v", done)
	}
	c := s.Current()
	if c.Hosts["shop.example"].Mode != config.ModeBlock || c.Mode != config.ModeLearn {
		t.Fatalf("graduation must set the host to block and keep learning for new hosts: %+v", c)
	}
	if r := callInspect(t, s, payload("GET", "/?q="+q("<script>alert(1)</script>"), "", withHost("shop.example", ""))); r.result.Action != "deny" {
		t.Fatalf("graduated host must block: %+v", r)
	}
	// A new host learns on its own clock.
	callInspect(t, s, payload("GET", "/", "", withHost("new.example", "")))
	if st := status(t, s, "new.example"); st.Learning == nil || st.Learning.State != "learning" || st.Learning.Day != 1 {
		t.Fatalf("new host must start its own period: %+v", st.Learning)
	}
	list, err := s.Changes(5)
	if err != nil || len(list) < 2 || !strings.Contains(list[0].Note, "Learning finished for shop.example") {
		t.Fatalf("graduation must be in the change history with a note: %+v %v", list, err)
	}
}

func TestOpenFindingWithLoginHoldsHostUntilResolved(t *testing.T) {
	s, ck := learningService(t, 7)
	// A logged-in user of the app gets reported by the method rule three times.
	for i := 0; i < SuggestMethodAfter-1; i++ {
		callInspect(t, s, patch("mm.example", "/api/v2/boards/8f3k2m9q1x7d4b6p/blocks/c2", withLogin()))
	}
	st := status(t, s, "mm.example")
	if st.Open != 1 || len(st.Suggest) != 0 {
		t.Fatalf("one open finding, no suggestion before %d hits: %+v", SuggestMethodAfter, st)
	}
	if st.Findings[0].Path != "/api/v2/boards/*/blocks/c2" || st.Findings[0].WithLogin != SuggestMethodAfter-1 {
		t.Fatalf("finding must group ID-like path segments and count logins: %+v", st.Findings[0])
	}
	callInspect(t, s, patch("mm.example", "/api/v2/boards/zz99zz99zz99zz99/blocks/c2", withLogin()))
	st = status(t, s, "mm.example")
	if len(st.Suggest) != 1 || st.Suggest[0].Method != "PATCH" || st.Suggest[0].Count != SuggestMethodAfter {
		t.Fatalf("PATCH suggestion must appear after %d hits: %+v", SuggestMethodAfter, st.Suggest)
	}
	ck.Add(8 * 24 * time.Hour)
	if done := s.LearningTick(); len(done) != 0 {
		t.Fatalf("open finding must hold the host: %v", done)
	}
	if st := status(t, s, "mm.example"); st.Learning.State != "held" {
		t.Fatalf("state must be held: %+v", st.Learning)
	}
	// Allowing the method resolves the finding; the host then switches.
	if _, err := s.Apply(func(c *config.Config) error {
		c.Hosts["mm.example"] = config.HostOverride{Mode: config.ModeInherit, Methods: []string{"PATCH"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st = status(t, s, "mm.example")
	if st.Open != 0 || st.Findings[0].Status != "resolved" || len(st.Suggest) != 0 || st.Learning.State != "ready" {
		t.Fatalf("allowed method must resolve the finding: %+v %+v", st.Findings, st.Learning)
	}
	if done := s.LearningTick(); len(done) != 1 {
		t.Fatalf("resolved host must switch: %v", done)
	}
	if c := s.Current(); c.Hosts["mm.example"].Mode != config.ModeBlock || len(c.Hosts["mm.example"].Methods) != 1 {
		t.Fatalf("graduation must keep the host's methods: %+v", c.Hosts["mm.example"])
	}
}

func TestDismissedFindingNoLongerHolds(t *testing.T) {
	s, ck := learningService(t, 1)
	callInspect(t, s, payload("GET", "/?q="+q("<script>alert(1)</script>"), "", withHost("app.example", ""), withLogin()))
	st := status(t, s, "app.example")
	if st.Open != 1 {
		t.Fatalf("attack with login must be open: %+v", st.Findings)
	}
	ck.Add(25 * time.Hour)
	if s.LearningTick() != nil {
		t.Fatal("held host switched")
	}
	if err := s.DismissFinding("app.example", st.Findings[0].Key, true); err != nil {
		t.Fatal(err)
	}
	if err := s.DismissFinding("app.example", "nope", true); err == nil {
		t.Fatal("unknown finding accepted")
	}
	if st := status(t, s, "app.example"); st.Open != 0 || st.Findings[0].Status != "dismissed" {
		t.Fatalf("dismissed finding: %+v", st.Findings)
	}
	if done := s.LearningTick(); len(done) != 1 {
		t.Fatalf("host must switch after dismissal: %v", done)
	}
	// Restart learning puts it back with a fresh period and no findings.
	if _, err := s.RestartLearning("app.example"); err != nil {
		t.Fatal(err)
	}
	if st := status(t, s, "app.example"); st.Mode != config.ModeLearn || st.Learning.State != "waiting" || len(st.Findings) != 0 {
		t.Fatalf("restart: %+v %+v", st, st.Learning)
	}
}

func TestActivationIsRequiredOnceAndBlockNeedsRisk(t *testing.T) {
	s := newSvc(t, Options{MaintenanceEvery: -1})
	if !s.Current().SetupRequired() {
		t.Fatal("fresh install must require activation")
	}
	if _, err := s.Activate(config.ModeBlock, 0, false); err == nil {
		t.Fatal("block without risk confirmation accepted")
	}
	if _, err := s.Activate(config.ModeLearn, 0, false); err == nil {
		t.Fatal("0 learning days accepted")
	}
	c, err := s.Activate(config.ModeBlock, 0, true)
	if err != nil || c.Mode != config.ModeBlock || c.Learning.ActivatedAt.IsZero() || c.SetupRequired() {
		t.Fatalf("block now: %+v %v", c, err)
	}
	if _, err := s.Activate(config.ModeLearn, 7, false); !errors.Is(err, ErrAlreadyActive) {
		t.Fatalf("second activation: %v", err)
	}
	// A rollback to the pre-activation revision keeps the activation fact.
	list, _ := s.Changes(5)
	if !strings.Contains(list[0].Note, "risk accepted") {
		t.Fatalf("activation note missing: %+v", list)
	}
}

func TestEnteringLearningStartsAFreshPeriod(t *testing.T) {
	s, ck := learningService(t, 7)
	callInspect(t, s, payload("GET", "/", "", withHost("shop.example", "")))
	setMode(t, s, config.ModeReport)
	ck.Add(10 * 24 * time.Hour)
	setMode(t, s, config.ModeLearn)
	callInspect(t, s, payload("GET", "/", "", withHost("shop.example", "")))
	if st := status(t, s, "shop.example"); st.Learning.State != "learning" || st.Learning.Requests != 1 {
		t.Fatalf("old learning record must not count after re-entering learning: %+v", st.Learning)
	}
}

func TestLearningRecordSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	ck := newClock()
	s := newSvc(t, Options{DataDir: dir, Now: ck.Now, MaintenanceEvery: -1})
	if _, err := s.Activate(config.ModeLearn, 7, false); err != nil {
		t.Fatal(err)
	}
	callInspect(t, s, payload("GET", "/?q="+q("<script>alert(1)</script>"), "", withHost("shop.example", ""), withLogin()))
	s.Close()
	s2 := newSvc(t, Options{DataDir: dir, Now: ck.Now, MaintenanceEvery: -1})
	st := status(t, s2, "shop.example")
	if st.Learning == nil || st.Learning.Requests != 1 || st.Open != 1 || s2.Learning().LoadError() != "" {
		t.Fatalf("learning record lost on restart: %+v %+v", st, st.Learning)
	}
}

type fakeRoutes struct {
	routes []zoraxy.Route
	tags   []string
	err    error
	calls  int
}

func (f *fakeRoutes) Routes(context.Context) ([]zoraxy.Route, []string, error) {
	f.calls++
	return f.routes, f.tags, f.err
}

func TestHostListFollowsZoraxyRoutes(t *testing.T) {
	s, _ := learningService(t, 7)
	src := &fakeRoutes{tags: []string{"waf"}, routes: []zoraxy.Route{
		{Host: "mm.example", Aliases: []string{"chat.example"}, Tags: []string{"waf"}, Protected: true},
		{Host: "static.example"},
		{Host: "old.example", Tags: []string{"waf"}, Protected: true, Disabled: true},
	}}
	s.SetRouteSource(src)
	rows, info := s.HostStatuses(time.Minute)
	if !info.Loaded || src.calls != 1 || len(info.Tags) != 1 {
		t.Fatalf("route list not loaded: %+v calls=%d", info, src.calls)
	}
	byHost := map[string]HostStatus{}
	for _, r := range rows {
		byHost[r.Host] = r
	}
	if r := byHost["chat.example"]; !r.InZoraxy || r.Route != "mm.example" || !r.Protected || r.Learning == nil || r.Learning.State != "waiting" {
		t.Fatalf("alias row: %+v", r)
	}
	if r := byHost["static.example"]; r.Protected || r.Learning != nil {
		t.Fatalf("untagged route must not be learning: %+v", r)
	}
	if r := byHost["old.example"]; r.Learning != nil {
		t.Fatalf("disabled route must not be learning: %+v", r)
	}
	if sum := SummarizeLearning(rows); sum.Hosts != 2 || sum.Learning != 2 {
		t.Fatalf("summary must count the protected, enabled hosts: %+v", sum)
	}
	// Cached within maxAge; a failing refresh keeps the last good list.
	s.HostStatuses(time.Minute)
	if src.calls != 1 {
		t.Fatalf("route list refreshed too often: %d", src.calls)
	}
	src.err = errors.New("Zoraxy API not reachable")
	s.RefreshRoutes(context.Background())
	rows, info = s.HostStatuses(0)
	if info.Error == "" || len(rows) != 4 {
		t.Fatalf("failed refresh must keep the list and report the error: %+v rows=%d", info, len(rows))
	}
}

// Review findings: restart cannot bypass activation and resets atomically;
// grouped findings need a covering exception; login is judged on all headers.
func TestRestartNeedsActivationAndStartsAFreshPeriodAtOnce(t *testing.T) {
	fresh := newSvc(t, Options{MaintenanceEvery: -1})
	if _, err := fresh.RestartLearning("shop.example"); !errors.Is(err, ErrActivationRequired) {
		t.Fatalf("restart on a fresh install: %v", err)
	}
	if !fresh.Current().SetupRequired() {
		t.Fatal("restart switched a fresh install on")
	}
	s, ck := learningService(t, 1)
	callInspect(t, s, payload("GET", "/", "", withHost("shop.example", "")))
	ck.Add(25 * time.Hour)
	if done := s.LearningTick(); len(done) != 1 {
		t.Fatalf("precondition: host must graduate: %v", done)
	}
	ck.Add(48 * time.Hour)
	if _, err := s.RestartLearning("shop.example"); err != nil {
		t.Fatal(err)
	}
	if done := s.LearningTick(); len(done) != 0 {
		t.Fatalf("restarted host must not graduate on its old period: %v", done)
	}
}

func TestGroupedFindingNeedsCoveringException(t *testing.T) {
	s, ck := learningService(t, 1)
	xss := "?q=" + q("<script>alert(1)</script>")
	for _, id := range []string{"8f3k2m9q1x7d4b6p", "zz99zz99zz99zz99"} {
		callInspect(t, s, payload("GET", "/items/"+id+xss, "", withHost("app.example", ""), withLogin()))
	}
	st := status(t, s, "app.example")
	if len(st.Findings) != 1 || st.Findings[0].Path != "/items/*" || st.Findings[0].ExceptionPath != "/items/*" || st.Open != 1 {
		t.Fatalf("grouped finding: %+v", st.Findings)
	}
	exc := func(path string) {
		t.Helper()
		if _, err := s.Apply(func(c *config.Config) error {
			c.Exceptions = nil
			for _, r := range st.Findings[0].Rules {
				c.Exceptions = append(c.Exceptions, config.Exception{ID: fmt.Sprintf("x%d", r.ID), RuleID: r.ID, Host: "app.example", Path: path, Argument: r.Argument, Reason: "test", CreatedAt: ck.Now(), ExpiresAt: ck.Now().Add(240 * time.Hour)})
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	exc("/items/zz99zz99zz99zz99") // exact: covers one of the two paths only
	if st := status(t, s, "app.example"); st.Open != 1 {
		t.Fatalf("exact exception for one example must not resolve the pattern: %+v", st.Findings)
	}
	exc("/items/*")
	if st := status(t, s, "app.example"); st.Open != 0 || st.Findings[0].Status != "resolved" {
		t.Fatalf("prefix exception must resolve the pattern: %+v", st.Findings)
	}
	ck.Add(25 * time.Hour)
	if done := s.LearningTick(); len(done) != 1 {
		t.Fatalf("resolved host must graduate: %v", done)
	}
}

func TestMethodFindingResolvedByCoveringException(t *testing.T) {
	s, ck := learningService(t, 7)
	callInspect(t, s, patch("mm.example", "/api/v4/posts/8f3k2m9q1x7d4b6p", withLogin()))
	if _, err := s.Apply(func(c *config.Config) error {
		c.Exceptions = append(c.Exceptions, config.Exception{ID: "m1", RuleID: config.MethodRuleID, Host: "mm.example", Method: "PATCH", Path: "/api/v4/posts/*", Reason: "test", CreatedAt: ck.Now(), ExpiresAt: ck.Now().Add(240 * time.Hour)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if st := status(t, s, "mm.example"); st.Open != 0 || st.Findings[0].Status != "resolved" {
		t.Fatalf("method finding covered by an exception: %+v", st.Findings)
	}
}

func TestLoginJudgedOnAllHeaderNames(t *testing.T) {
	s, _ := learningService(t, 7)
	p := payload("GET", "/?q="+q("<script>alert(1)</script>"), "", withHost("app.example", ""), withLogin())
	for i := 0; i < 70; i++ {
		p.Header[fmt.Sprintf("A-%02d", i)] = []string{"x"}
	}
	callInspect(t, s, p)
	if st := status(t, s, "app.example"); st.Open != 1 {
		t.Fatalf("cookie beyond the 64 stored header names must still count as login: %+v", st.Findings)
	}
}

func TestGraduationRefusesAHostThatIsGone(t *testing.T) {
	s, _ := learningService(t, 7)
	rev := s.Current().Revision
	if err := s.graduate("ghost.example", &LearnState{Days: 7}); err == nil {
		t.Fatal("graduated a host that has no record, route or override")
	}
	if c := s.Current(); c.Revision != rev || len(c.Hosts) != 0 {
		t.Fatalf("refused graduation changed the configuration: %+v", c.Hosts)
	}
}

func TestFailedRestartKeepsTheLearningRecord(t *testing.T) {
	ck := newClock()
	var fail atomic.Bool
	s := newSvc(t, Options{Now: ck.Now, MaintenanceEvery: -1, Build: func(c config.Config) (engine.Engine, error) {
		if fail.Load() {
			return nil, errors.New("compile failed")
		}
		return build(c)
	}})
	if _, err := s.Activate(config.ModeLearn, 7, false); err != nil {
		t.Fatal(err)
	}
	callInspect(t, s, payload("GET", "/?q="+q("<script>alert(1)</script>"), "", withHost("app.example", ""), withLogin()))
	fail.Store(true)
	if _, err := s.RestartLearning("app.example"); err == nil {
		t.Fatal("restart with a failing engine build must fail")
	}
	if st := status(t, s, "app.example"); st.Open != 1 || st.Learning.Requests != 1 {
		t.Fatalf("failed restart cleared the record: %+v", st)
	}
}

// Round 3: activation on a fresh install without data directory, and a
// failed save (learning write or config write) keeps the learning record.
func TestActivationCreatesTheDataDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plugin", "data")
	s := newSvc(t, Options{DataDir: dir, MaintenanceEvery: -1})
	if _, err := s.Activate(config.ModeLearn, 7, false); err != nil {
		t.Fatalf("activation on a fresh install: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "learning.json")); err != nil {
		t.Fatalf("learning record not written: %v", err)
	}
}

func TestFailedWritesKeepTheLearningRecord(t *testing.T) {
	for _, broken := range []string{"config.json", "learning.json"} {
		t.Run(broken, func(t *testing.T) {
			dir := t.TempDir()
			ck := newClock()
			s := newSvc(t, Options{DataDir: dir, Now: ck.Now, MaintenanceEvery: -1})
			if _, err := s.Activate(config.ModeLearn, 7, false); err != nil {
				t.Fatal(err)
			}
			callInspect(t, s, payload("GET", "/?q="+q("<script>alert(1)</script>"), "", withHost("app.example", ""), withLogin()))
			s.Learning().Flush()
			// Make the file unwritable by putting a directory in its place.
			p := filepath.Join(dir, broken)
			saved, _ := os.ReadFile(p)
			os.Remove(p)
			os.MkdirAll(filepath.Join(p, "x"), 0o700)
			if _, err := s.RestartLearning("app.example"); err == nil {
				t.Fatalf("restart must fail when %s cannot be written", broken)
			}
			if st := status(t, s, "app.example"); st.Open != 1 || st.Learning == nil || st.Learning.Requests != 1 {
				t.Fatalf("failed restart cleared the record in memory: %+v", st)
			}
			os.RemoveAll(p)
			os.WriteFile(p, saved, 0o600)
			s.Learning().Flush()
			if h := learningOpen(t, dir)["app.example"]; h.Requests != 1 || len(h.Findings) != 1 {
				t.Fatalf("failed restart cleared the record on disk: %+v", h)
			}
		})
	}
}

func learningOpen(t *testing.T, dir string) map[string]learning.Host {
	t.Helper()
	return learning.Open(dir).Snapshot()
}

// Switching report -> learn restarts the period but keeps what report mode
// found: those findings hold the host until resolved.
func TestEnteringLearningKeepsReportFindings(t *testing.T) {
	ck := newClock()
	s := newSvc(t, Options{Now: ck.Now, MaintenanceEvery: -1})
	setMode(t, s, config.ModeReport)
	callInspect(t, s, payload("GET", "/?q="+q("<script>alert(1)</script>"), "", withHost("app.example", ""), withLogin()))
	callInspect(t, s, payload("GET", "/", "", withHost("app.example", "")))
	ck.Add(10 * 24 * time.Hour)
	setMode(t, s, config.ModeLearn)
	st := status(t, s, "app.example")
	if st.Open != 1 || st.Learning == nil || st.Learning.State != "waiting" || st.Learning.Requests != 0 {
		t.Fatalf("report findings must survive and the period restart: open=%d learning=%+v", st.Open, st.Learning)
	}
	callInspect(t, s, payload("GET", "/", "", withHost("app.example", "")))
	st = status(t, s, "app.example")
	if st.Learning.State != "learning" || !st.Learning.Since.Equal(ck.Now()) || st.Open != 1 {
		t.Fatalf("period must start with the next request, findings kept: open=%d learning=%+v", st.Open, st.Learning)
	}
	// After the new period the kept finding holds the host until resolved.
	ck.Add(8 * 24 * time.Hour)
	if done := s.LearningTick(); len(done) != 0 {
		t.Fatalf("graduated with an open report finding: %v", done)
	}
	if err := s.DismissFinding("app.example", st.Findings[0].Key, true); err != nil {
		t.Fatal(err)
	}
	if done := s.LearningTick(); len(done) != 1 || done[0] != "app.example" {
		t.Fatalf("resolved host must graduate: %v", done)
	}
	setMode(t, s, config.ModeLearn, func(c *config.Config) { delete(c.Hosts, "app.example") })
	if st := status(t, s, "app.example"); st.Learning == nil || st.Learning.State != "waiting" {
		t.Fatalf("back to learning must start a new period: %+v", st.Learning)
	}
	// An explicit restart still clears the findings.
	if _, err := s.RestartLearning("app.example"); err != nil {
		t.Fatal(err)
	}
	if st := status(t, s, "app.example"); st.Open != 0 || len(st.Findings) != 0 {
		t.Fatalf("restart must clear findings: %+v", st)
	}
}

// The overview headline is built from these counts, so every inspected host
// lands in exactly one bucket and the next host carries its open findings.
func TestSummarizeLearningCountsEveryMode(t *testing.T) {
	soon, later := time.Unix(1000, 0), time.Unix(2000, 0)
	rows := []HostStatus{
		{Host: "a", Protected: true, Mode: config.ModeBlock},
		{Host: "b", Protected: true, Mode: config.ModeReport},
		{Host: "c", Protected: true, Mode: config.ModeOff},
		{Host: "d", Protected: true, Mode: config.ModeLearn, Open: 2, Learning: &LearnState{State: "learning", Until: soon}},
		{Host: "e", Protected: true, Mode: config.ModeLearn, Learning: &LearnState{State: "learning", Until: later}},
		{Host: "f", Mode: config.ModeBlock}, // not tagged: not counted
	}
	sum := SummarizeLearning(rows)
	if sum.Hosts != 5 || sum.Blocking != 1 || sum.Report != 1 || sum.Off != 1 || sum.Learning != 2 || sum.Open != 2 {
		t.Fatalf("counts %+v", sum)
	}
	if sum.NextHost != "d" || !sum.NextAt.Equal(soon) || sum.NextOpen != 2 {
		t.Fatalf("next host %+v", sum)
	}
}
