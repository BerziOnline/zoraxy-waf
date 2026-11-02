package profiles

import (
	"encoding/json"
	"testing"
	"testing/fstest"
)

func TestShippedProfiles(t *testing.T) {
	for _, p := range All() {
		t.Run(p.ID, func(t *testing.T) {
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestRejectBroadExceptions(t *testing.T) {
	p, _ := Get("mattermost")
	for name, change := range map[string]func(*Exception){"method": func(e *Exception) { e.Method = "" }, "path": func(e *Exception) { e.Path = "/*" }, "wildcard": func(e *Exception) { e.Path = "/a/*/b" }, "field": func(e *Exception) { e.Argument = "" }, "collection": func(e *Exception) { e.Argument = "ARGS:.*" }, "unknown": func(e *Exception) { e.Rules = []int{932999} }, "score": func(e *Exception) { e.Rules = []int{949110} }, "method-rule": func(e *Exception) { e.Rules = []int{911100} }, "reason": func(e *Exception) { e.Reason = "" },
		// Whole-request exceptions: only protocol rules, exact path, GET or HEAD.
		"whole-sqli": func(e *Exception) {
			e.Argument, e.Method, e.Path, e.Rules, e.TargetClass = "", "GET", "/api/v4/posts", []int{942100}, "sqli"
		},
		"whole-post": func(e *Exception) { e.Argument, e.Rules, e.TargetClass = "", []int{920420}, "protocol" },
		"whole-wildcard": func(e *Exception) {
			e.Argument, e.Method, e.Path, e.Rules, e.TargetClass = "", "GET", "/api/*", []int{920420}, "protocol"
		},
		"class-mismatch": func(e *Exception) { e.Rules = []int{942100} }} {
		t.Run(name, func(t *testing.T) {
			q := p
			q.Exceptions = append([]Exception{}, p.Exceptions...)
			change(&q.Exceptions[0])
			if q.Validate() == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
	b, _ := json.Marshal(p)
	b = append(b, []byte(` {}`)...)
	if _, err := Load(fstest.MapFS{"p.json": {Data: b}}); err == nil {
		t.Fatal("trailing data accepted")
	}
}
