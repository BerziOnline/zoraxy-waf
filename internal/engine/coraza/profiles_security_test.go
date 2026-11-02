package coraza

import (
	"encoding/json"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/profiles"
)

func TestProfileSecurityGate(t *testing.T) {
	b, err := os.ReadFile("testdata/profile-attacks.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus map[string][]string
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, v := range corpus {
		count += len(v)
	}
	if count < 20 {
		t.Fatal("corpus needs >=20 payloads")
	}
	family := profiles.ClassFamilies
	for _, p := range profiles.All() {
		for _, ex := range p.Exceptions {
			t.Run(p.ID+"/"+ex.Argument+ex.Path, func(t *testing.T) {
				opts := engine.Options{ParanoiaLevel: 1}
				// The profile's methods are allowed on the host the way the service
				// allows them: by removing the method rule for this transaction.
				if extra, _ := p.ExtraMethods(); slices.Contains(extra, ex.Method) {
					opts.Exclusions = append(opts.Exclusions, engine.Exclusion{RuleID: 911100})
				}
				// Classes deliberately targeted in this field by any entry of the profile.
				targeted := map[string]bool{}
				blind := map[string]string{}
				for _, x := range p.Exceptions {
					if x.Method == ex.Method && x.Path == ex.Path {
						for _, id := range x.Rules {
							opts.Exclusions = append(opts.Exclusions, engine.Exclusion{RuleID: id, Argument: x.Argument})
						}
						if x.Argument == ex.Argument {
							targeted[x.TargetClass] = true
							for c, r := range x.AcceptedBlindSpot {
								blind[c] = r
							}
						}
					}
				}
				// A clean request proves unrelated protocol rules do not mask a blind spot.
				field := strings.TrimPrefix(ex.Argument, "json.")
				makeRequest := func(value string) *engine.Request {
					if ex.Argument == "" {
						// Whole-request protocol exception on a bodyless request:
						// attacks arrive in the query, with the header the app sends.
						r := get(ex.Path + "?q=" + url.QueryEscape(value))
						r.Method = ex.Method
						r.Header["Content-Type"] = []string{"text/plain; charset=utf-8"}
						return r
					}
					body, _ := json.Marshal(map[string]string{field: value})
					r := post(strings.TrimSuffix(ex.Path, "*"), "application/json", string(body))
					r.Method = ex.Method
					return r
				}
				if inspect(t, makeRequest("A normal note"), opts).Interrupted {
					t.Fatal("clean control interrupted")
				}
				t.Log("class        blocked/total  sibling-family detections")
				for _, class := range []string{"command", "sqli", "xss", "traversal", "php", "rfi"} {
					payloads := corpus[class]
					if len(payloads) < 5 {
						t.Fatal("each class needs >=5 payloads")
					}
					caught, sibling := 0, 0
					f := family[class]
					for _, payload := range payloads {
						baseline := inspect(t, makeRequest(payload), engine.Options{ParanoiaLevel: 1, Exclusions: methodOnly(opts)})
						d := inspect(t, makeRequest(payload), opts)
						if !baseline.Interrupted || !hasRuleInRange(baseline, f[0], f[1]) {
							t.Logf("baseline %s %q: %v", class, payload, ruleIDs(baseline))
						}
						if d.Interrupted {
							caught++
						}
						if hasRuleInRange(d, f[0], f[1]) {
							sibling++
						}
						// Only detection the rule set had without the profile can be lost.
						detected := baseline.Interrupted && hasRuleInRange(baseline, f[0], f[1])
						if detected && !targeted[class] && blind[class] == "" && (!d.Interrupted || !hasRuleInRange(d, f[0], f[1])) {
							t.Errorf("%s payload escaped its detection class: %q rules=%v", class, payload, ruleIDs(d))
						}
					}
					t.Logf("%-12s %2d/%-2d         %d", class, caught, len(payloads), sibling)
					if sibling == 0 && blind[class] == "" && baselineSeen(t, corpus[class], makeRequest, methodOnly(opts), f) {
						t.Errorf("all %s detection lost; declare accepted_blind_spot with evidence/reason", class)
					}
				}
			})
		}
	}
}

// methodOnly keeps only the method-rule exclusion, so the baseline measures
// the rule set without the profile's field exceptions.
func methodOnly(o engine.Options) []engine.Exclusion {
	for _, e := range o.Exclusions {
		if e.RuleID == 911100 {
			return []engine.Exclusion{e}
		}
	}
	return nil
}

// baselineSeen reports whether the rule set without the profile detected the
// class at all in this field: only detection that existed can be lost.
func baselineSeen(t *testing.T, payloads []string, mk func(string) *engine.Request, ex []engine.Exclusion, f [2]int) bool {
	for _, p := range payloads {
		if d := inspect(t, mk(p), engine.Options{ParanoiaLevel: 1, Exclusions: ex}); d.Interrupted && hasRuleInRange(d, f[0], f[1]) {
			return true
		}
	}
	return false
}

// The Immich mobile app sends Content-Type text/plain on its bodyless version
// check. The Immich profile lets that request through; attacks on it still
// block. The path scope is tested in the service (TestImmichProfileScope).
func TestImmichProfileAllowsTheAppVersionCheckOnly(t *testing.T) {
	p, ok := profiles.Get("immich")
	if !ok {
		t.Fatal("immich profile missing")
	}
	var opts engine.Options
	for _, e := range p.Exceptions {
		if e.Method == "GET" && e.Path == "/api/server/version" {
			for _, id := range e.Rules {
				opts.Exclusions = append(opts.Exclusions, engine.Exclusion{RuleID: id, Argument: e.Argument})
			}
		}
	}
	app := func(path string) *engine.Request {
		r := get(path)
		r.Header["Content-Type"] = []string{"text/plain; charset=utf-8"}
		r.Header["User-Agent"] = []string{"immich-android/3.0.2"}
		return r
	}
	if d := inspect(t, app("/api/server/version"), engine.Options{}); !d.Interrupted || !hasRuleInRange(d, 920420, 920420) {
		t.Fatalf("without the profile CRS 920420 must block the app request: %v", ruleIDs(d))
	}
	if d := inspect(t, app("/api/server/version"), opts); d.Interrupted {
		t.Fatalf("with the profile the version check must pass: %v", ruleIDs(d))
	}
	if d := inspect(t, app("/api/server/version?q="+url.QueryEscape("' OR 1=1--")), opts); !d.Interrupted || !hasRuleInRange(d, 942000, 942999) {
		t.Fatalf("attacks on the version path must still block: %v", ruleIDs(d))
	}
}
