package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/events"
	"zoraxy-waf-plugin/internal/service"
)

// setup starts an already activated installation (mode off, revision 0), so
// the tests can switch modes with plain saves; freshSetup is a new install.
func setup(t *testing.T) (*service.Service, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	c := config.Default()
	c.Learning.ActivatedAt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	return start(t, dir)
}

func freshSetup(t *testing.T) (*service.Service, http.Handler) { return start(t, t.TempDir()) }

func start(t *testing.T, dir string) (*service.Service, http.Handler) {
	t.Helper()
	// Fake GC setter: admin tests must not depend on or change the GOGC of the test process.
	gc := 100
	s, err := service.New(service.Options{DataDir: dir, SetGCPercent: func(v int) int { old := gc; gc = v; return old }, MaintenanceEvery: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, Handler(s)
}

// An install that ran before activation existed (mode report, no activation
// time) counts as activated: off and back on must not bring the setup back.
func TestEnabledInstallWithoutActivationTimeStaysActivated(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Mode = config.ModeReport
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	s, h := start(t, dir)
	for _, mode := range []string{config.ModeOff, config.ModeReport, config.ModeBlock} {
		c = s.Current()
		c.Mode = mode
		b, _ := json.Marshal(c)
		if w := call(h, "PUT", "/ui/api/config", string(b), "trusted", "trusted"); w.Code != 200 {
			t.Fatalf("switch to %s: %d %s", mode, w.Code, w.Body)
		}
	}
	if s.Current().Learning.ActivatedAt.IsZero() {
		t.Fatal("the first save of an enabled install must record the activation")
	}
}

// A fresh install can only be switched on through the activation dialog:
// learning period (default 7 days) or block now with explicit risk.
func TestFreshInstallMustBeActivated(t *testing.T) {
	s, h := freshSetup(t)
	w := call(h, "GET", "/ui/api/state", "", "trusted", "")
	if !strings.Contains(w.Body.String(), `"setup_required":true`) || !strings.Contains(w.Body.String(), `"days":7`) {
		t.Fatalf("fresh state must require setup with 7 days default: %s", w.Body)
	}
	c := s.Current()
	c.Mode = config.ModeBlock
	b, _ := json.Marshal(c)
	if w := call(h, "PUT", "/ui/api/config", string(b), "trusted", "trusted"); w.Code != 409 || !strings.Contains(w.Body.String(), "activate the WAF first") {
		t.Fatalf("plain save switched a fresh install on: %d %s", w.Code, w.Body)
	}
	c = s.Current()
	c.Hosts["shop.example"] = config.HostOverride{Mode: config.ModeBlock}
	b, _ = json.Marshal(c)
	if w := call(h, "PUT", "/ui/api/config", string(b), "trusted", "trusted"); w.Code != 409 {
		t.Fatalf("host block on a fresh install bypassed activation: %d", w.Code)
	}
	if w := call(h, "POST", "/ui/api/hosts/restart", `{"host":"shop.example"}`, "trusted", "trusted"); w.Code != 409 {
		t.Fatalf("restart learning bypassed activation: %d %s", w.Code, w.Body)
	}
	if w := call(h, "POST", "/ui/api/activate", `{"mode":"block","days":7}`, "trusted", "trusted"); w.Code != 400 {
		t.Fatalf("block without risk confirmation = %d", w.Code)
	}
	if w := call(h, "POST", "/ui/api/activate", `{"mode":"learn","days":10}`, "trusted", "trusted"); w.Code != 200 {
		t.Fatalf("activate learn = %d %s", w.Code, w.Body)
	}
	if c := s.Current(); c.Mode != config.ModeLearn || c.Learning.Days != 10 || c.Learning.ActivatedAt.IsZero() {
		t.Fatalf("activation not applied: %+v", c.Learning)
	}
	if w := call(h, "POST", "/ui/api/activate", `{"mode":"learn","days":7}`, "trusted", "trusted"); w.Code != 409 {
		t.Fatalf("second activation = %d", w.Code)
	}
	// After activation, plain saves work again; the activation time is server-owned.
	c = s.Current()
	c.Mode = config.ModeReport
	c.Learning.ActivatedAt = time.Time{}
	b, _ = json.Marshal(c)
	if w := call(h, "PUT", "/ui/api/config", string(b), "trusted", "trusted"); w.Code != 200 {
		t.Fatalf("save after activation = %d %s", w.Code, w.Body)
	}
	if s.Current().Learning.ActivatedAt.IsZero() {
		t.Fatal("client cleared the activation time")
	}
	w = call(h, "GET", "/ui/api/hosts", "", "trusted", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"app_methods":["PUT","PATCH","DELETE"]`) || !strings.Contains(w.Body.String(), `"available":false`) {
		t.Fatalf("hosts endpoint: %d %s", w.Code, w.Body)
	}
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
	for _, text := range []string{`id="gc-target"`, `value="400"`, "Lab values on a 2-vCPU machine", "Detection stays the same"} {
		w := call(h, "GET", "/ui/", "", "token", "")
		if !strings.Contains(w.Body.String(), text) {
			t.Fatalf("UI missing %q", text)
		}
	}
}
