package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"zoraxy-waf-plugin/internal/config"
)

// TestChangeHistoryAndRollback: every save lands in the audit trail with a
// readable change list, secrets are never printed, and reverting to an
// earlier revision is itself a new audited revision.
func TestChangeHistoryAndRollback(t *testing.T) {
	s, h := setup(t)
	defer s.Close()
	put := func(mutate func(*config.Config)) config.Config {
		t.Helper()
		c := s.Current()
		mutate(&c)
		body, _ := json.Marshal(c)
		w := call(h, "PUT", "/ui/api/config", string(body), "tok", "tok")
		if w.Code != 200 {
			t.Fatalf("save failed: %d %s", w.Code, w.Body.String())
		}
		return s.Current()
	}
	put(func(c *config.Config) { c.Mode = "report"; c.CrowdSec.APIKey = "top-secret" })
	put(func(c *config.Config) {
		c.Mode = "block"
		c.Hosts["shop.example"] = config.HostOverride{Mode: "report"}
	})

	w := call(h, "GET", "/ui/api/changes", "", "tok", "")
	if w.Code != 200 {
		t.Fatalf("changes: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "top-secret") {
		t.Fatal("secret leaked into the change list")
	}
	var list []config.PublicHistoryEntry
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 2 || list[0].Revision != 2 || list[1].Revision != 1 {
		t.Fatalf("history wrong: %v %v", list, err)
	}
	fields := map[string]config.Change{}
	for _, c := range list[0].Changes {
		fields[c.Field] = c
	}
	if c := fields["mode"]; c.From != "report" || c.To != "block" {
		t.Fatalf("mode change missing: %v", list[0].Changes)
	}
	if _, ok := fields["hosts.shop.example.mode"]; !ok {
		t.Fatalf("host addition missing: %v", list[0].Changes)
	}

	// Roll back to revision 1: mode report, no host override, secret restored.
	w = call(h, "POST", "/ui/api/changes/revert", `{"revision":1}`, "tok", "tok")
	if w.Code != 200 {
		t.Fatalf("revert: %d %s", w.Code, w.Body.String())
	}
	cur := s.Current()
	if cur.Revision != 3 || cur.Mode != "report" || len(cur.Hosts) != 0 || cur.CrowdSec.APIKey != "top-secret" {
		t.Fatalf("rollback result wrong: rev %d mode %s hosts %d key %q", cur.Revision, cur.Mode, len(cur.Hosts), cur.CrowdSec.APIKey)
	}
	if strings.Contains(w.Body.String(), "top-secret") {
		t.Fatal("secret leaked in revert response")
	}
	w = call(h, "GET", "/ui/api/changes", "", "tok", "")
	list = nil
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 3 || list[0].Revision != 3 {
		t.Fatalf("rollback must be its own audited revision: %v", list)
	}
	for _, bad := range []string{`{"revision":0}`, `{"revision":99}`, `nonsense`} {
		w = call(h, "POST", "/ui/api/changes/revert", bad, "tok", "tok")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("revert %s must be rejected, got %d", bad, w.Code)
		}
	}
	if s.Current().Revision != 3 {
		t.Fatal("rejected reverts must not change the configuration")
	}
	// A stored snapshot the current build cannot activate (engine without
	// rule exclusions while the snapshot carries exceptions) must be
	// rejected with 4xx and leave configuration and history untouched.
	bad := s.Current()
	bad.Engine = "crowdsec"
	bad.CrowdSec.URL = "http://127.0.0.1:1/"
	bad.CrowdSec.APIKey = "k"
	bad.Exceptions = append(bad.Exceptions, config.Exception{ID: "x1", RuleID: 941100, Host: "shop.example", Path: "/search", Reason: "test", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	if err := config.AppendHistory(s.DataDir(), config.HistoryEntry{Time: time.Now(), Revision: 99, Snapshot: bad}); err != nil {
		t.Fatal(err)
	}
	w = call(h, "POST", "/ui/api/changes/revert", `{"revision":99}`, "tok", "tok")
	if w.Code != http.StatusUnprocessableEntity && w.Code != http.StatusBadRequest {
		t.Fatalf("revert of an unusable snapshot must be rejected, got %d %s", w.Code, w.Body.String())
	}
	if cur := s.Current(); cur.Revision != 3 || cur.Engine != "coraza" || cur.Mode != "report" {
		t.Fatalf("state changed after rejected revert: %+v", cur)
	}
	w = call(h, "GET", "/ui/api/changes", "", "tok", "")
	list = nil
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 4 || list[0].Revision != 99 {
		t.Fatalf("rejected revert must not append a revision (expected the 3 saves + the injected entry): %v", list)
	}
}
