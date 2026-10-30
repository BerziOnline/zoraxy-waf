package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zoraxy-waf-plugin/internal/alerts"
	"zoraxy-waf-plugin/internal/config"
)

// Sink tokens never reach the UI, a save without a token keeps the stored
// one, and the test button delivers to the configured receiver.
func TestAlertSinksTokenHandlingAndTestButton(t *testing.T) {
	got := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		b.Write(buf[:n])
		got <- r.Header.Get("Authorization") + "|" + b.String()
	}))
	defer srv.Close()
	s, h := setup(t)
	defer s.Close()
	c := s.Current()
	c.Alerts.Enabled = true
	c.Alerts.Sinks = []alerts.Sink{{ID: "mm", Name: "Mattermost", Format: "text", URL: srv.URL}, {ID: "api", Name: "Monitoring", Format: "json", URL: srv.URL, Token: "s3cret"}}
	body, _ := json.Marshal(c)
	if w := call(h, "PUT", "/ui/api/config", string(body), "tok", "tok"); w.Code != 200 || strings.Contains(w.Body.String(), "s3cret") || !strings.Contains(w.Body.String(), `"token":"stored"`) {
		t.Fatalf("save must succeed and mask the token: %d %s", w.Code, w.Body.String())
	}
	if w := call(h, "GET", "/ui/api/state", "", "tok", ""); strings.Contains(w.Body.String(), "s3cret") {
		t.Fatal("state must never expose sink tokens")
	}
	// Save again as the UI would: token "stored" → keeps s3cret.
	c = s.Current()
	pub := publicConfig(c)
	body, _ = json.Marshal(pub)
	if w := call(h, "PUT", "/ui/api/config", string(body), "tok", "tok"); w.Code != 200 {
		t.Fatalf("resave: %d %s", w.Code, w.Body.String())
	}
	if s.Current().Alerts.Sinks[1].Token != "s3cret" {
		t.Fatal("stored token must survive a save from the UI")
	}
	if w := call(h, "POST", "/ui/api/alerts/test", "{}", "tok", "tok"); w.Code != 200 {
		t.Fatalf("test alert: %d %s", w.Code, w.Body.String())
	}
	a, b := <-got, <-got
	if !(strings.Contains(a+b, `"text":"**Zoraxy WAF – Test alert**`) && strings.Contains(a+b, `Bearer s3cret|{"v":1`)) {
		t.Fatalf("both sinks must receive the test alert in their format: %q %q", a, b)
	}
	var st alerts.Stats
	_ = json.Unmarshal(call(h, "GET", "/ui/api/state", "", "tok", "").Body.Bytes(), &struct {
		AlertStats *alerts.Stats `json:"alert_stats"`
	}{&st})
	if st.Sent != 2 || st.Failed != 0 {
		t.Fatalf("alert stats wrong: %+v", st)
	}
	// Invalid sink is rejected (generic reason by design), config unchanged.
	c = s.Current()
	c.Alerts.Sinks[0].URL = "ftp://nope"
	body, _ = json.Marshal(c)
	if w := call(h, "PUT", "/ui/api/config", string(body), "tok", "tok"); w.Code != 400 {
		t.Fatalf("invalid sink must be rejected: %d %s", w.Code, w.Body.String())
	}
	if s.Current().Alerts.Sinks[0].URL == "ftp://nope" {
		t.Fatal("rejected save must not change the configuration")
	}
	_ = config.Default()
}
