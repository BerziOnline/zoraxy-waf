package service

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
)

// Keep this gate below the baseline's 71 allocations without coupling it to
// the exact current count. Measure the same recorder path as BenchmarkLayers;
// request marshaling, configuration and engine compilation are outside it.
func TestAllowPathAllocationBudget(t *testing.T) {
	s := newSvc(t, Options{Build: func(config.Config) (engine.Engine, error) { return &fakeEngine{}, nil }})
	setMode(t, s, config.ModeBlock)
	raw, err := json.Marshal(payload("POST", "/submit", "name=Alice&city=Berlin&quantity=2"))
	if err != nil {
		t.Fatal(err)
	}
	h := s.IPCHandler()
	allocs := testing.AllocsPerRun(100, func() {
		r := httptest.NewRequest("POST", "http://127.0.0.1/inspect", bytes.NewReader(raw))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("HTTP %d", w.Code)
		}
	})
	t.Logf("allow allocations/request: %.1f (budget %d; baseline 72 without race instrumentation)", allocs, allowAllocationBudget)
	if allocs > float64(allowAllocationBudget) {
		t.Fatalf("allow-path audit work regressed: %.1f allocations > %d", allocs, allowAllocationBudget)
	}
}
