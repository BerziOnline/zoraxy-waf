package admin

import (
	"encoding/json"
	"testing"
	"time"
	"zoraxy-waf-plugin/internal/config"
)

func TestCrowdSecRejectsNewLocalExceptions(t *testing.T) {
	s, h := setup(t)
	c := s.Current()
	c.Engine = config.EngineCrowdSec
	c.CrowdSec = config.CrowdSecSettings{URL: "http://127.0.0.1:7422/", APIKey: "fixture-key", TimeoutMS: 500}
	now := time.Now()
	c.Exceptions = []config.Exception{{ID: "unsupported", RuleID: 942100, Host: "shop.example", Path: "/search", Reason: "test scope", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}}
	b, _ := json.Marshal(c)
	w := call(h, "PUT", "/ui/api/config", string(b), "token", "token")
	if w.Code != 422 {
		t.Fatalf("unsupported exceptions accepted: %d %s", w.Code, w.Body)
	}
	if s.Current().Engine != config.EngineCoraza {
		t.Fatal("rejected config published")
	}
}
func TestNarrowScopeRequiredByAdmin(t *testing.T) {
	s, h := setup(t)
	c := s.Current()
	now := time.Now()
	c.Exceptions = []config.Exception{{ID: "broad", RuleID: 942100, Host: "shop.example", Reason: "test scope", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}}
	b, _ := json.Marshal(c)
	if w := call(h, "PUT", "/ui/api/config", string(b), "token", "token"); w.Code != 400 {
		t.Fatalf("pathless exception = %d", w.Code)
	}
}
