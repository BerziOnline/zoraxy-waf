package coraza

import (
	"context"
	"testing"
	"zoraxy-waf-plugin/internal/crsplugins"
	"zoraxy-waf-plugin/internal/engine"
)

func TestOfficialPluginsCompileAndRemainHostScoped(t *testing.T) {
	hosts := map[string][]string{}
	for _, p := range crsplugins.Manifest() {
		if p.Shipped {
			hosts[p.Name] = []string{"cloud.example.test"}
		}
	}
	e, err := NewWithPlugins([]int{1}, 5, hosts)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	inspectWith := func(host string, r *engine.Request) engine.Decision {
		r.Host = host
		d, err := e.Inspect(context.Background(), r, engine.Options{ParanoiaLevel: 1})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	for _, host := range []string{"cloud.example.test", "CLOUD.EXAMPLE.TEST.:443"} {
		d := inspectWith(host, withMethod("PROPFIND", get("/remote.php/dav/files/user/Documents/")))
		if d.Interrupted {
			t.Errorf("profiled WebDAV false positive: %v", ruleIDs(d))
		}
	}
	for _, host := range []string{"other.example.test", "cloudXexample.test", "cloud.example.test.attacker.test", "prefixcloud.example.test"} {
		d := inspectWith(host, withMethod("PROPFIND", get("/remote.php/dav/files/user/Documents/")))
		if !d.Interrupted || !hasRuleInRange(d, 911100, 911100) {
			t.Errorf("plugin leaked onto %s: %v", host, ruleIDs(d))
		}
	}
	for _, a := range attacks {
		for _, host := range []string{"cloud.example.test", "other.example.test"} {
			d := inspectWith(host, get("/search?"+a.param+"="+q(a.value)))
			if !d.Interrupted {
				t.Errorf("attack %s escaped on %s: %v", a.name, host, ruleIDs(d))
			}
		}
	}
	d := inspectWith("cloud.example.test", withMethod("TRACE", get("/remote.php/dav/files/user/")))
	if !d.Interrupted {
		t.Fatal("upstream package must not permit TRACE")
	}
}
