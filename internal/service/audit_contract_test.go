package service

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/events"
)

// Runs unchanged on baseline b202064 and current code. Only unpredictable ID,
// request elapsed time and elapsed-time percentile are normalized; EVERY other
// response, event and counter field is retained in the canonical JSON fixture.
func TestAuditContractFixture(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	type row struct {
		Name     string
		Response ipcResp
		Events   []events.Event
		Stats    Stats
	}
	rows := []row{}
	for _, name := range []string{"allow", "block", "would-block", "oversize-block", "oversize-report", "error", "exceptions"} {
		f := &fakeEngine{}
		if name == "block" || name == "would-block" || name == "exceptions" {
			f.decision = engine.Decision{Interrupted: true, Status: 403, AnomalyScore: 5, RuleDetails: true, Matches: []engine.Match{{RuleID: 941100, Message: "matched supersecretvalue", Severity: "CRITICAL", Phase: 2, Tags: []string{"attack-xss"}, Targets: []string{"ARGS:q"}}}}
		}
		if name == "error" {
			f.err = errors.New("must not leak engine detail")
		}
		s := newSvc(t, Options{Now: func() time.Time { return now }, Build: func(config.Config) (engine.Engine, error) { return f, nil }})
		mode := config.ModeBlock
		if name == "would-block" || name == "oversize-report" {
			mode = config.ModeReport
		}
		setMode(t, s, mode, func(c *config.Config) {
			c.MaxBodyKB = 1
			if name == "exceptions" {
				c.Exceptions = []config.Exception{{ID: "fixture-ex", RuleID: 941100, Host: "shop.example", Method: "POST", Path: "/submit", Argument: "q", Reason: "test-only fake-engine exception", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			}
		})
		p := payload("POST", "/submit?q=supersecretvalue", "q=supersecretvalue&password=anothersecret")
		p.Header["Cookie"] = []string{"session=cookiesupersecret"}
		p.Header["Authorization"] = []string{"Bearer headersecret"}
		if strings.HasPrefix(name, "oversize") {
			p.Body = []byte("data=" + strings.Repeat("a", 2000))
		}
		r := callInspect(t, s, p)
		if r.result.EventID != "" {
			r.raw = strings.ReplaceAll(r.raw, r.result.EventID, "")
		}
		r.result.EventID = ""
		ev := s.Events().List(events.Filter{})
		for i := range ev {
			ev[i].ID = ""
			ev[i].DurationMS = 0
		}
		st := s.Stats()
		st.LatencyP95MS = 0
		rows = append(rows, row{Name: name, Response: r, Events: ev, Stats: st})
	}
	// ipcResp fields are private; encode them explicitly instead of accidentally
	// producing empty JSON response objects.
	output := []any{}
	for _, r := range rows {
		output = append(output, map[string]any{"name": r.Name, "code": r.Response.code, "raw": r.Response.raw, "result": r.Response.result, "events": r.Events, "stats": r.Stats})
	}
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "supersecretvalue") || strings.Contains(string(data), "anothersecret") || strings.Contains(string(data), "headersecret") || strings.Contains(string(data), "cookiesupersecret") {
		t.Fatal("redaction regression")
	}
	if path := os.Getenv("AUDIT_CONTRACT_OUTPUT"); path != "" {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
