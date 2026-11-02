package zoraxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeZoraxy answers the two plugin API endpoints like Zoraxy does: Bearer
// key required, proxy list as Go field names, plugin groups as tag -> IDs.
func fakeZoraxy(t *testing.T, key string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+key || r.Method != "GET" {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch r.URL.Path {
		case EndpointProxyList:
			if r.URL.Query().Get("type") != "host" {
				w.Write([]byte(`{"error":"type not defined"}`))
				return
			}
			w.Write([]byte(`[{"ProxyType":1,"RootOrMatchingDomain":"Immich.Example","MatchingDomainAlias":["photos.example",""],"Tags":["waf"],"Disabled":false,"ActiveOrigins":[{"OriginIpOrDomain":"10.0.0.1:2283"}]},
{"ProxyType":1,"RootOrMatchingDomain":"static.example","MatchingDomainAlias":null,"Tags":["other"],"Disabled":false},
{"ProxyType":1,"RootOrMatchingDomain":"old.example","Tags":["waf"],"Disabled":true}]`))
		case EndpointPluginGroups:
			w.Write([]byte(`{"waf":["org.zoraxy.waf"],"other":["org.example.ratelimit"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestRoutesReadsRoutesAndProtectingTags(t *testing.T) {
	srv := fakeZoraxy(t, "k1")
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, APIKey: "k1", PluginID: "org.zoraxy.waf", HTTP: srv.Client()}
	routes, tags, err := c.Routes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 1 || tags[0] != "waf" || len(routes) != 3 {
		t.Fatalf("tags %v routes %+v", tags, routes)
	}
	im := routes[0]
	if im.Host != "immich.example" || !im.Protected || len(im.Aliases) != 1 || im.Aliases[0] != "photos.example" {
		t.Fatalf("immich route: %+v", im)
	}
	for _, r := range routes {
		if r.Host == "static.example" && r.Protected {
			t.Fatal("route tagged for another plugin counted as protected")
		}
		if r.Host == "old.example" && !r.Disabled {
			t.Fatal("disabled flag lost")
		}
	}
	bad := &Client{BaseURL: srv.URL, APIKey: "wrong", PluginID: "org.zoraxy.waf", HTTP: srv.Client()}
	if _, _, err := bad.Routes(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong key: %v", err)
	}
	if New(0, "k", "id") != nil || New(8000, "", "id") != nil {
		t.Fatal("client without port or key must be nil")
	}
}

// Zoraxy may listen on a LAN address only; the client falls through dead
// candidates to the one that answers and keeps using it.
func TestRoutesFallsBackToTheAddressZoraxyListensOn(t *testing.T) {
	srv := fakeZoraxy(t, "k1")
	defer srv.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	c := &Client{BaseURL: deadURL, Candidates: []string{deadURL, srv.URL}, APIKey: "k1", PluginID: "org.zoraxy.waf", HTTP: srv.Client()}
	if _, _, err := c.Routes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != srv.URL {
		t.Fatalf("working address not kept: %s", c.BaseURL)
	}
	gone := &Client{BaseURL: deadURL, Candidates: []string{deadURL}, APIKey: "k1", HTTP: srv.Client()}
	if _, _, err := gone.Routes(context.Background()); err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("unreachable Zoraxy: %v", err)
	}
	// A live but unrelated service on the first address must not hide Zoraxy.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>other</html>")) }))
	defer other.Close()
	c2 := &Client{BaseURL: other.URL, Candidates: []string{other.URL, srv.URL}, APIKey: "k1", PluginID: "org.zoraxy.waf", HTTP: srv.Client()}
	if routes, _, err := c2.Routes(context.Background()); err != nil || len(routes) != 3 || c2.BaseURL != srv.URL {
		t.Fatalf("unrelated first responder pinned: %v %s", err, c2.BaseURL)
	}
	if n := New(8000, "k", "id"); n == nil || n.Candidates[0] != "http://127.0.0.1:8000" || len(n.Candidates) < 2 {
		t.Fatalf("candidates: %+v", n)
	}
}
