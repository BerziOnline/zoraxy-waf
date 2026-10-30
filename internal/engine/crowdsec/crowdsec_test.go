package crowdsec

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"zoraxy-waf-plugin/internal/engine"
)

const apiKey = "appsec-key-DO-NOT-LEAK"

type recorded struct {
	method string
	header http.Header
	body   []byte
	path   string
}

// mockAppSec implements the documented AppSec component contract:
// 200 {"action":"allow"}, 403 {"action":"ban","http_status":403}, 401 on bad key.
func mockAppSec(t *testing.T, respond func(r *http.Request) (int, string)) (*httptest.Server, func() []recorded) {
	t.Helper()
	var mu sync.Mutex
	var got []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, recorded{r.Method, r.Header.Clone(), b, r.URL.Path})
		mu.Unlock()
		if r.Header.Get("X-Crowdsec-Appsec-Api-Key") != apiKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		code, body := respond(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []recorded { mu.Lock(); defer mu.Unlock(); return append([]recorded{}, got...) }
}

func newEngine(t *testing.T, url, key string) *Engine {
	t.Helper()
	e, err := New(Config{URL: url, APIKey: key, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func request(body string) *engine.Request {
	return &engine.Request{
		ID: "r1", Method: "POST", RawURI: "/login?next=%2Fhome", Proto: "HTTP/1.1", Host: "shop.example",
		ClientIP: "203.0.113.50",
		Header: map[string][]string{
			"User-Agent":              {"Mozilla/5.0 test"},
			"Content-Type":            {"application/x-www-form-urlencoded"},
			"Cookie":                  {"sid=abc"},
			"X-Crowdsec-Appsec-Ip":    {"10.66.66.66"}, // spoofed by the client
			"X-Crowdsec-Appsec-Extra": {"spoof"},
			"Connection":              {"keep-alive"},
		},
		Body: []byte(body),
	}
}

func TestPostWithBodyAndTrustedMetadataOverride(t *testing.T) {
	srv, got := mockAppSec(t, func(*http.Request) (int, string) { return 200, `{"action":"allow"}` })
	e := newEngine(t, srv.URL+"/", apiKey)
	d, err := e.Inspect(context.Background(), request("user=alice&pw=x"), engine.Options{})
	if err != nil || d.Interrupted {
		t.Fatalf("allow expected: %+v %v", d, err)
	}
	r := got()[0]
	if r.method != "POST" || string(r.body) != "user=alice&pw=x" {
		t.Fatalf("POST/body not forwarded: %s %q", r.method, r.body)
	}
	want := map[string]string{
		"X-Crowdsec-Appsec-Ip":           "203.0.113.50",
		"X-Crowdsec-Appsec-Uri":          "/login?next=%2Fhome",
		"X-Crowdsec-Appsec-Host":         "shop.example",
		"X-Crowdsec-Appsec-Verb":         "POST",
		"X-Crowdsec-Appsec-Api-Key":      apiKey,
		"X-Crowdsec-Appsec-User-Agent":   "Mozilla/5.0 test",
		"X-Crowdsec-Appsec-Http-Version": "11",
		"Cookie":                         "sid=abc",
		"Content-Type":                   "application/x-www-form-urlencoded",
	}
	for k, v := range want {
		if got := r.header.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("header %s = %v, want [%s]", k, got, v)
		}
	}
	if r.header.Get("X-Crowdsec-Appsec-Extra") != "" {
		t.Error("client-supplied X-Crowdsec-Appsec-* header forwarded")
	}
}

func TestGetWithoutBody(t *testing.T) {
	srv, got := mockAppSec(t, func(*http.Request) (int, string) { return 200, `{"action":"allow"}` })
	e := newEngine(t, srv.URL, apiKey)
	req := request("")
	req.Method = "GET"
	req.Body = nil
	if _, err := e.Inspect(context.Background(), req, engine.Options{}); err != nil {
		t.Fatal(err)
	}
	r := got()[0]
	if r.method != "GET" || len(r.body) != 0 || r.header.Get("X-Crowdsec-Appsec-Verb") != "GET" {
		t.Fatalf("GET contract violated: %s %q", r.method, r.body)
	}
}

func TestBanDecision(t *testing.T) {
	srv, _ := mockAppSec(t, func(*http.Request) (int, string) { return 403, `{"action":"ban","http_status":403}` })
	d, err := newEngine(t, srv.URL, apiKey).Inspect(context.Background(), request("q=1"), engine.Options{})
	if err != nil || !d.Interrupted || d.Status != 403 || d.Action != "ban" || d.RuleDetails {
		t.Fatalf("ban: %+v %v", d, err)
	}
	srv2, _ := mockAppSec(t, func(*http.Request) (int, string) { return 403, `{"action":"ban","http_status":200}` })
	d, err = newEngine(t, srv2.URL, apiKey).Inspect(context.Background(), request("q=1"), engine.Options{})
	if err != nil || d.Status != 403 {
		t.Fatalf("invalid http_status must fall back to 403: %+v %v", d, err)
	}
}

func TestErrorsAreFailuresNotDecisions(t *testing.T) {
	cases := map[string]func(*http.Request) (int, string){
		"captcha":     func(*http.Request) (int, string) { return 403, `{"action":"captcha","http_status":403}` },
		"challenge":   func(*http.Request) (int, string) { return 403, `{"action":"challenge"}` },
		"500":         func(*http.Request) (int, string) { return 500, `null` },
		"bad json":    func(*http.Request) (int, string) { return 200, `{"action":` },
		"unknown 200": func(*http.Request) (int, string) { return 200, `{"action":"ban"}` },
		"unknown 403": func(*http.Request) (int, string) { return 403, `{"action":"teleport"}` },
		"oversized": func(*http.Request) (int, string) {
			return 200, `{"action":"allow","pad":"` + strings.Repeat("x", 8192) + `"}`
		},
		"unexpected 204": func(*http.Request) (int, string) { return 204, `` },
	}
	for name, fn := range cases {
		srv, _ := mockAppSec(t, fn)
		_, err := newEngine(t, srv.URL, apiKey).Inspect(context.Background(), request("q=1"), engine.Options{})
		if err == nil {
			t.Errorf("%s: expected error", name)
		}
		if (name == "captcha" || name == "challenge") && !errors.Is(err, engine.ErrChallenge) {
			t.Errorf("%s: want ErrChallenge, got %v", name, err)
		}
	}
}

func TestUnauthorizedDoesNotLeakKey(t *testing.T) {
	srv, _ := mockAppSec(t, nil)
	e := newEngine(t, srv.URL, "wrong-key-SECRET")
	_, err := e.Inspect(context.Background(), request("q=1"), engine.Options{})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("401 must be an error: %v", err)
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(e.Health().Detail, "SECRET") {
		t.Fatal("API key leaked into error/health")
	}
	if e.Health().OK {
		t.Fatal("health must report the failure")
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
	defer target.Close()
	srv, _ := mockAppSec(t, nil)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redir.Close()
	_ = srv
	_, err := newEngine(t, redir.URL, apiKey).Inspect(context.Background(), request("q=1"), engine.Options{})
	if err == nil || followed {
		t.Fatalf("redirect followed=%v err=%v", followed, err)
	}
}

func TestNoProxyFromEnvironment(t *testing.T) {
	e := newEngine(t, "http://127.0.0.1:1/", apiKey)
	tr, ok := e.client.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatal("transport must not use a proxy")
	}
	if e.client.CheckRedirect == nil {
		t.Fatal("redirect policy missing")
	}
}

func TestTimeoutAndContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	e, _ := New(Config{URL: srv.URL, APIKey: apiKey, Timeout: 100 * time.Millisecond})
	defer e.Close()
	start := time.Now()
	if _, err := e.Inspect(context.Background(), request("q=1"), engine.Options{}); err == nil {
		t.Fatal("timeout not reported")
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout not bounded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Inspect(ctx, request("q=1"), engine.Options{}); err == nil {
		t.Fatal("cancelled context accepted")
	}
}

func TestRuleExclusionsRejected(t *testing.T) {
	srv, got := mockAppSec(t, func(*http.Request) (int, string) { return 200, `{"action":"allow"}` })
	e := newEngine(t, srv.URL, apiKey)
	_, err := e.Inspect(context.Background(), request("q=1"), engine.Options{Exclusions: []engine.Exclusion{{RuleID: 942100}}})
	if !errors.Is(err, engine.ErrUnsupported) || len(got()) != 0 {
		t.Fatalf("exclusions must be rejected before contacting AppSec: %v", err)
	}
	c := e.Capabilities()
	if c.Name != "crowdsec" || c.RuleExclusions || c.Challenge || c.RuleDetails || !c.RequestBody {
		t.Fatalf("capabilities %+v", c)
	}
}

func TestTLSRemoteAndHTTPOnlyLoopback(t *testing.T) {
	if _, err := New(Config{URL: "http://appsec.example:7422/", APIKey: apiKey, Timeout: time.Second}); err == nil {
		t.Fatal("remote plain HTTP accepted")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"action":"allow"}`)
	}))
	defer srv.Close()
	e, err := New(Config{URL: srv.URL, APIKey: apiKey, Timeout: time.Second, RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := e.Inspect(context.Background(), request(""), engine.Options{}); err != nil {
		t.Fatalf("TLS AppSec: %v", err)
	}
	// Untrusted certificate must fail.
	e2, _ := New(Config{URL: srv.URL, APIKey: apiKey, Timeout: time.Second})
	defer e2.Close()
	if _, err := e2.Inspect(context.Background(), request(""), engine.Options{}); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}

func TestHealthRecoversAfterSuccess(t *testing.T) {
	fail := true
	var mu sync.Mutex
	srv, _ := mockAppSec(t, func(*http.Request) (int, string) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return 500, ""
		}
		return 200, `{"action":"allow"}`
	})
	e := newEngine(t, srv.URL, apiKey)
	e.Inspect(context.Background(), request(""), engine.Options{})
	if e.Health().OK {
		t.Fatal("health ok after failure")
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	e.Inspect(context.Background(), request(""), engine.Options{})
	if !e.Health().OK {
		t.Fatalf("health not recovered: %+v", e.Health())
	}
}
