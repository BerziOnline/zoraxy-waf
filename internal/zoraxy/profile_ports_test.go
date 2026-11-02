package zoraxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestRouteUpstreamPortsAreReadOnlyHints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("route detection attempted a write")
		}
		if r.URL.Path == EndpointPluginGroups {
			w.Write([]byte(`{"waf":["waf-plugin"]}`))
			return
		}
		w.Write([]byte(`[{"RootOrMatchingDomain":"chat.example.test","MatchingDomainAlias":["alias.example.test"],"Tags":["waf"],"ActiveOrigins":[{"OriginIpOrDomain":"backend.example.test:8065"},{"OriginIpOrDomain":"[2001:db8::1]:9443"},{"OriginIpOrDomain":"duplicate.example.test:8065"},{"OriginIpOrDomain":"invalid"},{"OriginIpOrDomain":"invalid:70000"}],"InactiveOrigins":[{"OriginIpOrDomain":"old.example.test:2283"}]}]`))
	}))
	defer server.Close()
	c := Client{BaseURL: server.URL, HTTP: server.Client(), PluginID: "waf-plugin"}
	routes, _, err := c.Routes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || !reflect.DeepEqual(routes[0].UpstreamPorts, []int{8065, 9443}) || len(routes[0].Aliases) != 1 {
		t.Fatal(routes)
	}
}
