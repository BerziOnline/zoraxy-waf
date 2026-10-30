package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"zoraxy-waf-plugin/internal/service"
	"zoraxy-waf-plugin/internal/wire"
)

func TestIntrospectionMatchesCoreHook(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-introspect"}, &out); err != nil {
		t.Fatal(err)
	}
	var p wire.IntroSpect
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.RequestInspect != "/inspect" || p.RequestInspectPolicy != "/policy" || p.RequestInspectMaxBody != 64 || p.UIPath != "/ui" || p.Type != wire.PluginTypeRouter || p.ID == "" || len(p.StaticCapturePaths) > 0 {
		t.Fatalf("incorrect contract: %+v", p)
	}
}
func TestRequiresConfigure(t *testing.T) {
	if err := run(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("must require Zoraxy startup configuration")
	}
}
func TestRoutesSeparateCoreUIAndTermination(t *testing.T) {
	s, e := service.New(service.Options{DataDir: t.TempDir()})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	stopped := false
	h := routes(s, func() { stopped = true })
	request := func(path, host, token, origin string) int {
		r := httptest.NewRequest("GET", "http://127.0.0.1"+path, nil)
		r.Host = host
		if token != "" {
			r.Header.Set("X-Zoraxy-Csrf", token)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := request("/policy", "127.0.0.1:18000", "", ""); c != 200 {
		t.Fatal("core policy", c)
	}
	if c := request("/ui/api/state", "zoraxy.example:8000", "session-token", ""); c != 200 {
		t.Fatal("UI proxy must retain admin host", c)
	}
	if c := request("/ui/term", "zoraxy.example:8000", "session-token", ""); c != 403 || stopped {
		t.Fatal("browser proxy can stop plugin", c)
	}
	if c := request("/ui/term", "127.0.0.1:18000", "", "https://evil.example"); c != 403 || stopped {
		t.Fatal("cross origin stop", c)
	}
	if c := request("/ui/term", "127.0.0.1:18000", "", ""); c != 200 || !stopped {
		t.Fatal("core termination", c)
	}
}
