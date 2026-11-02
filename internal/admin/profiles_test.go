package admin

import (
	"encoding/json"
	"strings"
	"testing"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/profiles"
)

func TestProfileAPIRequiresReviewAndCSRF(t *testing.T) {
	s, h := setup(t)
	request := `{"host":"chat.example.test","id":"mattermost","action":"apply","confirm_methods":true,"revision":0}`
	if w := call(h, "POST", "/ui/api/profiles/change", request, "trusted", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := call(h, "GET", "/ui/api/profiles/preview?host=chat.example.test&id=mattermost", "", "trusted", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"json.message"`) {
		t.Fatal(w.Code, w.Body)
	}
	if len(s.Current().Exceptions) != 0 {
		t.Fatal("preview changed policy")
	}
	for _, bad := range []string{strings.Replace(request, `"confirm_methods":true`, `"confirm_methods":false`, 1), request + ` {}`, strings.Replace(request, `"host":"chat.example.test"`, `"host":"*.example.test"`, 1)} {
		if w := call(h, "POST", "/ui/api/profiles/change", bad, "trusted", "trusted"); w.Code != 400 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if w := call(h, "POST", "/ui/api/profiles/change", request, "trusted", "trusted"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if p, _ := profiles.Get("mattermost"); s.Current().Revision != 1 || len(s.Current().Exceptions) != profileRuleCount(p) {
		t.Fatal("not one atomic change")
	}
	if w := call(h, "POST", "/ui/api/profiles/change", request, "trusted", "trusted"); w.Code != 409 {
		t.Fatal("stale review accepted", w.Code)
	}
	c := s.Current()
	c.Engine = config.EngineCrowdSec
	c.CrowdSec.URL = "http://127.0.0.1:7422"
	c.CrowdSec.APIKey = "fixture-only"
	b, _ := json.Marshal(c)
	if w := call(h, "PUT", "/ui/api/config", string(b), "trusted", "trusted"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := call(h, "GET", "/ui/api/profiles", "", "trusted", ""); w.Code != 200 || strings.Contains(w.Body.String(), `"nextcloud"`) {
		t.Fatal("Coraza-only profile offered", w.Code, w.Body)
	}
	if w := call(h, "GET", "/ui/api/profiles/preview?host=cloud.example.test&id=nextcloud", "", "trusted", ""); w.Code != 422 {
		t.Fatal("Coraza-only preview accepted", w.Code)
	}
}

func profileRuleCount(p profiles.Profile) (n int) {
	for _, e := range p.Exceptions {
		n += len(e.Rules)
	}
	return n
}
