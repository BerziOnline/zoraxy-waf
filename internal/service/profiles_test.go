package service

import (
	"testing"
	"time"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/events"
	"zoraxy-waf-plugin/internal/learning"
	"zoraxy-waf-plugin/internal/profiles"
	"zoraxy-waf-plugin/internal/wire"
	"zoraxy-waf-plugin/internal/zoraxy"
)

func TestApplyProfileResolvesGroupedFindings(t *testing.T) {
	s, ck := learningService(t, 7)
	host := "chat.example.test"
	for _, x := range []struct {
		path, arg string
		ids       []int
	}{{"/api/v4/posts", "json.message", []int{932125, 932380}}, {"/plugins/playbooks/api/v0/query", "json.query", []int{932235}}, {"/other", "json.message", []int{941100}}} {
		ev := events.Event{Time: ck.Now(), Host: host, Method: "POST", Path: x.path}
		for _, id := range x.ids {
			ev.Matches = append(ev.Matches, engine.Match{RuleID: id, Targets: []string{"ARGS_POST:" + x.arg}})
		}
		s.Learning().Record(host, ev, true)
	}
	if status(t, s, host).Open != 3 {
		t.Fatal("fixture must have three open findings")
	}
	rev := s.Current().Revision
	if _, err := s.ApplyProfile(host, "mattermost", false, rev); err == nil {
		t.Fatal("method widening needs consent")
	}
	c, err := s.ApplyProfile(host, "mattermost", true, rev)
	if err != nil {
		t.Fatal(err)
	}
	if c.Revision != rev+1 || len(c.Exceptions) != mattermostRules(t) || status(t, s, host).Open != 1 {
		t.Fatalf("profile must resolve exactly two grouped findings: %+v", status(t, s, host))
	}
	for _, e := range c.Exceptions {
		if e.Source != mattermostSource(t) || e.Argument == "" || e.ExpiresAt.Sub(e.CreatedAt) != config.MaxExceptionLife {
			t.Fatal(e)
		}
	}
	again, err := s.ApplyProfile(host, "mattermost", true, c.Revision)
	if err != nil || len(again.Exceptions) != mattermostRules(t) {
		t.Fatalf("not idempotent: %v", err)
	}
	if _, err := s.RemoveProfile(host, "mattermost", again.Revision); err != nil {
		t.Fatal(err)
	}
	c = s.Current()
	if len(c.Exceptions) != 0 || len(c.Hosts[host].Methods) != 3 || status(t, s, host).Open != 3 {
		t.Fatal("remove must undo only profile exceptions, keep methods")
	}
	hist, _ := s.Changes(10)
	if len(hist) == 0 || hist[0].Note != "Removed service profile Mattermost from chat.example.test (methods kept)" {
		t.Fatal(hist)
	}
}
func TestProfileDetectionNeedsRepeatedLoginEvidence(t *testing.T) {
	c := config.Default()
	rec := map[string]learning.Host{"chat.example.test": {Requests: 10, Paths: map[string]int{"/api/v4/posts": 1}}}
	rt := []zoraxy.Route{{Host: "chat.example.test", Protected: true, UpstreamPorts: []int{8065}}}
	rows := hostStatuses(c, rt, RouteInfo{Loaded: true}, rec, time.Now())
	if len(rows[0].SuggestedProfiles) != 0 {
		t.Fatal("one request is not evidence")
	}
	h := rec["chat.example.test"]
	h.Paths["/api/v4/posts"] = 3
	rec["chat.example.test"] = h
	rows = hostStatuses(c, rt, RouteInfo{Loaded: true}, rec, time.Now())
	if len(rows[0].SuggestedProfiles) != 1 || rows[0].SuggestedProfiles[0].ID != "mattermost" {
		t.Fatal(rows)
	}
	c.Hosts["chat.example.test"] = config.HostOverride{Mode: "inherit", DismissedProfiles: []string{"mattermost"}}
	rows = hostStatuses(c, rt, RouteInfo{Loaded: true}, rec, time.Now())
	if len(rows[0].SuggestedProfiles) != 0 {
		t.Fatal("dismissed suggestion returned")
	}
}

// mattermostRules is the number of exceptions the shipped Mattermost profile
// materialises (one per rule), so tests follow catalogue updates.
func mattermostRules(t *testing.T) (n int) {
	t.Helper()
	p, ok := profiles.Get("mattermost")
	if !ok {
		t.Fatal("mattermost profile missing")
	}
	for _, e := range p.Exceptions {
		n += len(e.Rules)
	}
	return n
}

// mattermostSource is the Source the shipped Mattermost profile writes.
func mattermostSource(t *testing.T) string {
	t.Helper()
	p, _ := profiles.Get("mattermost")
	return profileSource(p.ID, p.Version)
}

// TestImmichProfileScope: the Immich profile lets the mobile app's version
// check (Content-Type text/plain, no body) through on exactly that path.
func TestImmichProfileScope(t *testing.T) {
	s := newSvc(t, Options{})
	setMode(t, s, config.ModeBlock)
	app := func(path string) wire.InspectPayload {
		p := payload("GET", path, "")
		p.Header["Content-Type"] = []string{"text/plain; charset=utf-8"}
		p.Header["User-Agent"] = []string{"immich-android/3.0.2"}
		return p
	}
	if code, _ := postSniff(t, s, app("/api/server/version")); code != wire.SniffDeny {
		t.Fatalf("without the profile CRS blocks the version check, got %d", code)
	}
	if _, err := s.ApplyProfile("shop.example", "immich", true, s.Current().Revision); err != nil {
		t.Fatal(err)
	}
	if code, _ := postSniff(t, s, app("/api/server/version")); code != wire.SniffSkip {
		t.Fatalf("with the profile the version check must pass, got %d", code)
	}
	for _, path := range []string{"/api/server/about", "/api/server/versionx", "/api/server/version/x"} {
		if code, _ := postSniff(t, s, app(path)); code != wire.SniffDeny {
			t.Fatalf("the exception must not reach %s, got %d", path, code)
		}
	}
	if code, _ := postSniff(t, s, app("/api/server/version?client=android")); code != wire.SniffSkip {
		t.Fatalf("a query string must not break the exception, got %d", code)
	}
	p := app("/api/server/version")
	p.Host, p.Hostname, p.RouteID = "other.example", "other.example", "other.example"
	if code, _ := postSniff(t, s, p); code != wire.SniffDeny {
		t.Fatalf("the exception must not reach other hosts, got %d", code)
	}
}
