package admin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/events"
)

func TestSummaryAndWidgetFromRealState(t *testing.T) {
	s, h := setup(t)
	now := time.Now()
	add := func(id, host, ip, action string, rule int) {
		s.Events().Add(events.Event{ID: id, Time: now, Host: host, ClientIP: ip, Method: "GET", Path: "/p", Engine: "coraza", Action: action,
			Matches: []engine.Match{{RuleID: 949110, Message: "anomaly"}, {RuleID: rule, Message: "rule " + id}}})
		s.History().Record(action)
	}
	add("a", "shop.example", "10.0.0.1", events.ActionWouldBlock, 942100)
	add("b", "shop.example", "10.0.0.1", events.ActionWouldBlock, 942100)
	add("c", "blog.example", "10.0.0.2", events.ActionWouldBlock, 941100)
	s.Events().Add(events.Event{ID: "d", Time: now, Host: "blog.example", Action: events.ActionError})
	s.History().Record(events.ActionError)
	s.History().Record(events.ActionAllowed)

	w := call(h, "GET", "/ui/api/summary", "", "token", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var sum Summary
	if err := json.Unmarshal(w.Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Window.Events != 4 || sum.History.Today.Attacks() != 3 || sum.History.Today.Allowed != 1 || sum.History.H24.Error != 1 {
		t.Fatalf("window/history: %+v %+v", sum.Window, sum.History.Today)
	}
	if len(sum.Categories) != 2 || sum.Categories[0].Key != "SQL injection" || sum.Categories[0].Count != 2 || sum.Categories[1].Key != "Cross-site scripting (XSS)" {
		t.Fatalf("categories %+v", sum.Categories)
	}
	if sum.TopHosts[0].Key != "shop.example" || sum.TopHosts[0].Count != 2 || sum.TopIPs[0].Key != "10.0.0.1" {
		t.Fatalf("top %+v %+v", sum.TopHosts, sum.TopIPs)
	}
	if sum.TopRules[0].Key != "942100" || !strings.HasPrefix(sum.TopRules[0].Label, "rule ") || sum.TopRules[0].Count != 2 {
		t.Fatalf("rules %+v (scoring rule 949110 must not win)", sum.TopRules)
	}
	// Fresh install: engine ok, mode off, no hosts, no exceptions, feed healthy -> 20+15+10+15 = 60.
	if sum.Protection.Score != 60 || len(sum.Protection.Items) != 5 {
		t.Fatalf("protection %+v", sum.Protection)
	}
	for _, it := range sum.Protection.Items {
		if it.ID == "mode" && (it.OK || it.Hint == "" || it.Tab != "settings") {
			t.Fatalf("mode item must be actionable: %+v", it)
		}
	}

	// Block mode, one host off, one expired exception -> 20+40+0+0+15 = 75.
	c := s.Current()
	c.Mode = config.ModeBlock
	c.Hosts["old.example"] = config.HostOverride{Mode: config.ModeOff}
	c.Exceptions = append(c.Exceptions, config.Exception{ID: "x", RuleID: 942100, Host: "shop.example", Path: "/p", Reason: "test", CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour)})
	b, _ := json.Marshal(c)
	if w := call(h, "PUT", "/ui/api/config", string(b), "token", "token"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	sum = summarize(s, now, time.Local)
	if sum.Protection.Score != 75 || sum.Exceptions.Expired != 1 || len(sum.HostsOff) != 1 {
		t.Fatalf("protection after change: %d %+v %+v", sum.Protection.Score, sum.Exceptions, sum.HostsOff)
	}

	w = call(h, "GET", "/ui/api/widget", "", "token", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var wd Widget
	if err := json.Unmarshal(w.Body.Bytes(), &wd); err != nil {
		t.Fatal(err)
	}
	if wd.State != "ok" || wd.Headline != "Blocking attacks" || len(wd.Metrics) != 4 || wd.Metrics[0].Value != "3" || len(wd.Spark) != 24 || wd.Bars[0].Label != "SQL injection" {
		t.Fatalf("widget %+v", wd)
	}
	if wd.Metrics[0].Note != "no 7-day reference yet" {
		t.Fatalf("a first-day install has no complete day to average: %q", wd.Metrics[0].Note)
	}
	if w := call(h, "GET", "/ui/api/widget", "", "", ""); w.Code != 403 {
		t.Fatal("widget must stay behind the Zoraxy proxy", w.Code)
	}
}
