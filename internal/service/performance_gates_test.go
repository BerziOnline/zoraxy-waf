package service

import (
	"sync/atomic"
	"testing"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
)

type countedHealthEngine struct {
	fakeEngine
	healthCalls atomic.Int64
}

func (f *countedHealthEngine) Health() engine.Health {
	f.healthCalls.Add(1)
	return engine.Health{OK: true, RuleSet: "counted"}
}
func TestAllowedDoesNotBuildAuditMetadata(t *testing.T) {
	f := &countedHealthEngine{}
	s := newSvc(t, Options{Build: func(config.Config) (engine.Engine, error) { return f, nil }})
	setMode(t, s, config.ModeBlock)
	before := f.healthCalls.Load()
	if r := callInspect(t, s, payload("POST", "/submit", "name=Alice")); r.code != 200 || r.result.EventID != "" {
		t.Fatal(r)
	}
	if got := f.healthCalls.Load() - before; got != 0 {
		t.Fatalf("allowed request consulted audit health %d times", got)
	}
	f.decision = engine.Decision{Interrupted: true, Status: 403, RuleDetails: true, AnomalyScore: 5, Matches: []engine.Match{{RuleID: 941100, Message: "XSS"}}}
	r := callInspect(t, s, payload("GET", "/search?q=bad", ""))
	if r.result.Action != "deny" {
		t.Fatal(r)
	}
	ev, ok := s.Events().Get(r.result.EventID)
	if !ok || ev.RuleSet != "counted" || ev.AnomalyScore != 5 || ev.Status != 403 || len(ev.Matches) != 1 {
		t.Fatalf("event changed: %+v", ev)
	}
	if got := f.healthCalls.Load() - before; got != 1 {
		t.Fatalf("blocked audit health=%d", got)
	}
}
