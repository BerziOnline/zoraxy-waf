package alerts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type receiver struct {
	mu     sync.Mutex
	bodies []string
	auth   []string
	status int
}

func (r *receiver) handler(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.bodies = append(r.bodies, string(b))
	r.auth = append(r.auth, req.Header.Get("Authorization"))
	r.mu.Unlock()
	if r.status != 0 {
		w.WriteHeader(r.status)
	}
}

func (r *receiver) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.bodies) }

func TestBurstCooldownAndFormats(t *testing.T) {
	rc := &receiver{}
	srv := httptest.NewServer(http.HandlerFunc(rc.handler))
	defer srv.Close()
	clock := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	n := New("waf-test", func() time.Time { return clock })
	s := Defaults()
	s.Enabled, s.BurstCount, s.BurstWindowMin, s.CooldownMin = true, 10, 5, 30
	s.Sinks = []Sink{{ID: "a", Name: "json", Format: "json", URL: srv.URL, Token: "tok"}, {ID: "b", Name: "chat", Format: "text", URL: srv.URL}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	n.Apply(s)
	probe := Probe{EngineOK: true}
	n.Tick(context.Background(), probe) // baseline sample
	for i := 0; i < 9; i++ {
		n.RecordAttack()
	}
	clock = clock.Add(time.Minute)
	n.Tick(context.Background(), probe)
	if rc.count() != 0 {
		t.Fatalf("9 attacks must not trigger a burst of 10, got %d deliveries", rc.count())
	}
	n.RecordAttack()
	clock = clock.Add(time.Minute)
	n.Tick(context.Background(), probe)
	if rc.count() != 2 {
		t.Fatalf("burst must reach both sinks, got %d", rc.count())
	}
	var a Alert
	if err := json.Unmarshal([]byte(rc.bodies[0]), &a); err != nil || a.Key != "burst" || a.Severity != "critical" || a.Source != "waf-test" || a.Fields["attacks"] != "10" {
		t.Fatalf("json sink payload wrong: %s %v", rc.bodies[0], err)
	}
	if rc.auth[0] != "Bearer tok" || rc.auth[1] != "" {
		t.Fatalf("bearer token must only go to the sink that has one: %v", rc.auth)
	}
	if !strings.Contains(rc.bodies[1], `"text":"**waf-test – Attack burst** (critical)`) {
		t.Fatalf("text sink payload wrong: %s", rc.bodies[1])
	}
	// Still bursting 10 minutes later: cooldown (30 min) suppresses.
	for i := 0; i < 20; i++ {
		n.RecordAttack()
	}
	clock = clock.Add(10 * time.Minute)
	n.Tick(context.Background(), probe)
	if rc.count() != 2 {
		t.Fatalf("cooldown must suppress the repeat, got %d", rc.count())
	}
	clock = clock.Add(25 * time.Minute)
	for i := 0; i < 20; i++ {
		n.RecordAttack()
	}
	clock = clock.Add(time.Minute)
	n.Tick(context.Background(), probe)
	if rc.count() != 4 {
		t.Fatalf("after the cooldown a new burst must alert again, got %d", rc.count())
	}
	st := n.Stats()
	if st.Sent != 4 || st.Failed != 0 || st.LastError != "" {
		t.Fatalf("stats wrong: %+v", st)
	}
}

func TestEngineTransitionsExceptionsAndFailures(t *testing.T) {
	rc := &receiver{}
	srv := httptest.NewServer(http.HandlerFunc(rc.handler))
	defer srv.Close()
	clock := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	n := New("waf", func() time.Time { return clock })
	s := Defaults()
	s.Enabled, s.ExceptionExpiryDays = true, 3
	s.Sinks = []Sink{{ID: "a", Name: "json", Format: "json", URL: srv.URL}}
	n.Apply(s)
	n.Tick(context.Background(), Probe{EngineOK: true})
	if rc.count() != 0 {
		t.Fatal("a healthy engine on the first probe must not alert")
	}
	n.Tick(context.Background(), Probe{EngineOK: false, EngineDetail: "rules failed to compile"})
	n.Tick(context.Background(), Probe{EngineOK: false, EngineDetail: "rules failed to compile"})
	if rc.count() != 1 || !strings.Contains(rc.bodies[0], "Engine unhealthy") || !strings.Contains(rc.bodies[0], "rules failed to compile") {
		t.Fatalf("unhealthy transition must alert exactly once: %d %v", rc.count(), rc.bodies)
	}
	n.Tick(context.Background(), Probe{EngineOK: true})
	if rc.count() != 2 || !strings.Contains(rc.bodies[1], "Engine recovered") {
		t.Fatalf("recovery must alert: %d", rc.count())
	}
	ex := map[string]Expiring{"x1": {Label: "rule 941100 on shop.example /search", ExpiresAt: clock.Add(40 * time.Hour)}, "x2": {Label: "far", ExpiresAt: clock.Add(10 * 24 * time.Hour)}}
	n.Tick(context.Background(), Probe{EngineOK: true, Exceptions: ex})
	if rc.count() != 3 || !strings.Contains(rc.bodies[2], `"exception":"x1"`) || !strings.Contains(rc.bodies[2], "40 hours") {
		t.Fatalf("only the exception inside the window must alert: %d %v", rc.count(), rc.bodies[2:])
	}
	n.Tick(context.Background(), Probe{EngineOK: true, Exceptions: ex})
	if rc.count() != 3 {
		t.Fatal("exception warning must respect the cooldown")
	}
	// Receiver failure: counted, shown, never retried.
	rc.status = 500
	if err := n.Test(context.Background()); err == nil || !strings.Contains(err.Error(), "answered 500") {
		t.Fatalf("test alert must report the receiver error, got %v", err)
	}
	if st := n.Stats(); st.Failed != 1 || !strings.Contains(st.LastError, "json: receiver answered 500") {
		t.Fatalf("failure stats wrong: %+v", st)
	}
	// Disabled: nothing is sent, counters still work (free when off).
	s.Enabled = false
	s.Sinks = nil
	n.Apply(s)
	rc.status = 0
	for i := 0; i < 1000; i++ {
		n.RecordAttack()
	}
	clock = clock.Add(time.Minute)
	n.Tick(context.Background(), Probe{EngineOK: false})
	if rc.count() != 4 {
		t.Fatalf("disabled alerts must not deliver, got %d", rc.count())
	}
}

func TestValidateAndPublic(t *testing.T) {
	s := Defaults()
	if err := s.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	s.Enabled = true
	if err := s.Validate(); err == nil {
		t.Fatal("enabled without sink must fail")
	}
	s.Sinks = []Sink{{ID: "a", Format: "json", URL: "ftp://x"}}
	if err := s.Validate(); err == nil {
		t.Fatal("non-http url must fail")
	}
	s.Sinks = []Sink{{ID: "a", Format: "json", URL: "https://x", Token: "secret"}, {ID: "a", Format: "text", URL: "https://y"}}
	if err := s.Validate(); err == nil {
		t.Fatal("duplicate sink id must fail")
	}
	s.Sinks = s.Sinks[:1]
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if p := s.Public(); p.Sinks[0].Token != "stored" || s.Sinks[0].Token != "secret" {
		t.Fatalf("Public must mask tokens without touching the original: %+v %+v", p, s)
	}
}
