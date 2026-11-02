package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"zoraxy-waf-plugin/internal/config"
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
	if p.DynamicCaptureSniff != "/sniff" || p.DynamicCaptureIngress != "/capture" || p.RequestInspect != "" || p.UIPath != "/ui" || p.Type != wire.PluginTypeRouter || p.ID == "" || len(p.StaticCapturePaths) > 0 {
		t.Fatalf("incorrect contract: %+v", p)
	}
}

func TestIntrospectionAsksForTheLargestSavedBodySize(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ZORAXY_WAF_DATA_DIR", dir)
	if got := sniffBodyKB(); got != 64 {
		t.Fatalf("no saved settings: want the default 64 KiB, got %d", got)
	}
	c := config.Default()
	c.Hosts = map[string]config.HostOverride{"files.example": {Mode: config.ModeInherit, MaxBodyKB: 512}}
	if err := config.Save(filepath.Join(dir, "config.json"), c); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"-introspect"}, &out); err != nil {
		t.Fatal(err)
	}
	var p wire.IntroSpect
	if err := json.Unmarshal(out.Bytes(), &p); err != nil || p.DynamicCaptureSniffBodyKB != 512 {
		t.Fatalf("want dynamic_capture_sniff_body_kb 512, got %d (%v)", p.DynamicCaptureSniffBodyKB, err)
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
	if c := request("/sniff/", "127.0.0.1:18000", "", ""); c != 405 {
		t.Fatal("core sniff endpoint must be mounted (GET → 405, POST only)", c)
	}
	if c := request("/sniff/", "zoraxy.example:8000", "", ""); c != 403 {
		t.Fatal("sniff endpoint must be loopback-only", c)
	}
	if c := request("/capture/x", "127.0.0.1:18000", "", ""); c != 404 {
		t.Fatal("capture ingress must not serve traffic", c)
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
