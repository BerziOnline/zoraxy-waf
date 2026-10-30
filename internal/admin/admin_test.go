package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/events"
	"zoraxy-waf-plugin/internal/service"
)

func setup(t *testing.T) (*service.Service, http.Handler) {
	t.Helper()
	// Fake GC setter: admin tests must not depend on or change the GOGC of the test process.
	gc := 100
	s, err := service.New(service.Options{DataDir: t.TempDir(), SetGCPercent: func(v int) int { old := gc; gc = v; return old }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, Handler(s)
}
func call(h http.Handler, method, path, body, proxy, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://admin.example"+path, strings.NewReader(body))
	if proxy != "" {
		r.Header.Set("X-Zoraxy-Csrf", proxy)
	}
	if csrf != "" {
		r.Header.Set("X-WAF-CSRF", csrf)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestStateRequiresProxyAndMutationsRequireEcho(t *testing.T) {
	s, h := setup(t)
	if w := call(h, "GET", "/ui/api/state", "", "", ""); w.Code != 403 {
		t.Fatalf("direct admin = %d", w.Code)
	}
	w := call(h, "GET", "/ui/api/state", "", "trusted", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"capabilities"`) {
		t.Fatalf("state: %d %s", w.Code, w.Body)
	}
	c := s.Current()
	c.Mode = "report"
	b, _ := json.Marshal(c)
	for _, echo := range []string{"", "wrong"} {
		if w := call(h, "PUT", "/ui/api/config", string(b), "trusted", echo); w.Code != 403 {
			t.Fatalf("CSRF echo %q = %d", echo, w.Code)
		}
	}
	if s.Current().Mode != "off" {
		t.Fatal("CSRF mutated config")
	}
	if w := call(h, "PUT", "/ui/api/config", string(b), "trusted", "trusted"); w.Code != 200 {
		t.Fatalf("apply: %d %s", w.Code, w.Body)
	}
	if s.Current().Mode != "report" {
		t.Fatal("not applied")
	}
	if w := call(h, "PUT", "/ui/api/config", string(b), "trusted", "trusted"); w.Code != 409 {
		t.Fatalf("stale write = %d", w.Code)
	}
}
func TestConfigCRUDAndRejectedMutation(t *testing.T) {
	s, h := setup(t)
	c := s.Current()
	c.Hosts["shop.example"] = config.HostOverride{Mode: "block", ParanoiaLevel: 2}
	c.InvertFailureHosts = []string{"shop.example"}
	now := time.Now().UTC()
	c.Exceptions = append(c.Exceptions, config.Exception{ID: "test", RuleID: 942100, Host: "shop.example", Path: "/search", Reason: "false positive", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	b, _ := json.Marshal(c)
	w := call(h, "PUT", "/ui/api/config", string(b), "token", "token")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if !s.Current().Effective("shop.example", "").FailClosed || len(s.Current().Exceptions) != 1 {
		t.Fatal("policies not applied")
	}
	c = s.Current()
	c.MaxBodyKB = 5000
	b, _ = json.Marshal(c)
	if w := call(h, "PUT", "/ui/api/config", string(b), "token", "token"); w.Code != 400 {
		t.Fatal("invalid accepted", w.Code)
	}
	if s.Current().MaxBodyKB == 5000 {
		t.Fatal("invalid published")
	}
	c = s.Current()
	delete(c.Hosts, "shop.example")
	c.Exceptions = []config.Exception{}
	c.InvertFailureHosts = []string{}
	b, _ = json.Marshal(c)
	w = call(h, "PUT", "/ui/api/config", string(b), "token", "token")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if len(s.Current().Exceptions) != 0 || len(s.Current().Hosts) != 0 {
		t.Fatal("deletion failed")
	}
}
func TestStateMasksCrowdSecKeyAndPreservesBlank(t *testing.T) {
	s, h := setup(t)
	_, err := s.Apply(func(c *config.Config) error {
		c.CrowdSec = config.CrowdSecSettings{URL: "http://127.0.0.1:7422/", APIKey: "secret-never-render", TimeoutMS: 500}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	w := call(h, "GET", "/ui/api/state", "", "token", "")
	if bytes.Contains(w.Body.Bytes(), []byte("secret-never-render")) {
		t.Fatal("key exposed")
	}
	c := s.Current()
	c.CrowdSec.APIKey = ""
	c.Mode = "report"
	b, _ := json.Marshal(c)
	w = call(h, "PUT", "/ui/api/config", string(b), "token", "token")
	if w.Code != 200 || s.Current().CrowdSec.APIKey != "secret-never-render" {
		t.Fatal("blank did not preserve", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "secret-never-render") {
		t.Fatal("mutation response exposes key")
	}
}
func TestFilteredEventsExportAndSuggestionAreReadOnly(t *testing.T) {
	s, h := setup(t)
	ev := events.Event{ID: "one", Host: "shop.example", Path: "/search", Method: "GET", Engine: "coraza", Action: events.ActionWouldBlock, Matches: []engine.Match{{RuleID: 942100, Targets: []string{"ARGS_GET:q"}}}}
	s.Events().Add(ev)
	s.Events().Add(events.Event{ID: "two", Host: "other.example", Action: events.ActionError})
	w := call(h, "GET", "/ui/api/events?host=shop.example&rule_id=942100", "", "token", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "one") || strings.Contains(w.Body.String(), "two") {
		t.Fatal(w.Code, w.Body)
	}
	w = call(h, "GET", "/ui/api/events/one/suggestions", "", "token", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"argument":"q"`) {
		t.Fatal(w.Code, w.Body)
	}
	if len(s.Current().Exceptions) != 0 {
		t.Fatal("suggestion automatically activated")
	}
	w = call(h, "GET", "/ui/api/export?host=shop.example", "", "token", "")
	if w.Code != 200 || strings.Count(strings.TrimSpace(w.Body.String()), "\n") != 0 {
		t.Fatal(w.Code, w.Body)
	}
	if w := call(h, "GET", "/ui/api/events/missing/suggestions", "", "token", ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
}
func TestEmbeddedUIAndEscapedCSRF(t *testing.T) {
	_, h := setup(t)
	w := call(h, "GET", "/ui/", "", `token"><script>`, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), `content="token"><script>`) {
		t.Fatal("unsafe token", w.Code)
	}
	for _, path := range []string{"/ui/app.js", "/ui/style.css", "/ui/semantic.min.css"} {
		w := call(h, "GET", path, "", "token", "")
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
	}
}

func TestSpeedSavedThroughAdminAndReportedInState(t *testing.T) {
	s, h := setup(t)
	var st struct {
		Config         config.Config `json:"config"`
		GCPercent      int           `json:"gc_percent"`
		GCStartPercent int           `json:"gc_start_percent"`
		CPUCores       int           `json:"cpu_cores"`
	}
	read := func() {
		w := call(h, "GET", "/ui/api/state", "", "token", "")
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if st.Config.GCTarget != 400 || st.GCPercent != 400 || st.GCStartPercent != 100 || st.CPUCores < 1 {
		t.Fatalf("default: gc_target=%d gc_percent=%d start=%d cores=%d, want 400/400/100/>=1", st.Config.GCTarget, st.GCPercent, st.GCStartPercent, st.CPUCores)
	}
	c := s.Current()
	c.GCTarget = 800
	b, _ := json.Marshal(c)
	if w := call(h, "PUT", "/ui/api/config", string(b), "token", "token"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	read()
	if st.Config.GCTarget != 800 || st.GCPercent != 800 {
		t.Fatalf("after choosing 800: gc_target=%d gc_percent=%d", st.Config.GCTarget, st.GCPercent)
	}
	// Other forms save the whole config; the speed choice must survive an unrelated change.
	c = s.Current()
	c.FailClosed = !c.FailClosed
	b, _ = json.Marshal(publicConfig(c))
	if w := call(h, "PUT", "/ui/api/config", string(b), "token", "token"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	read()
	if st.Config.GCTarget != 800 || st.GCPercent != 800 {
		t.Fatalf("unrelated save dropped speed: %d %d", st.Config.GCTarget, st.GCPercent)
	}
	// Values outside the four levels are rejected and change nothing.
	c = s.Current()
	c.GCTarget = 300
	b, _ = json.Marshal(c)
	if w := call(h, "PUT", "/ui/api/config", string(b), "token", "token"); w.Code == 200 {
		t.Fatal("gc_target 300 accepted")
	}
	read()
	if st.GCPercent != 800 {
		t.Fatalf("rejected save changed runtime GC target to %d", st.GCPercent)
	}
	for _, text := range []string{`id="gc-target"`, `value="400"`, "Measured performance", "CPU cores", "Same rules, same detection"} {
		w := call(h, "GET", "/ui/", "", "token", "")
		if !strings.Contains(w.Body.String(), text) {
			t.Fatalf("UI missing %q", text)
		}
	}
}
