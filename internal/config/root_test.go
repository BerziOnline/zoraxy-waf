package config

import (
	"testing"
	"time"
)

func TestDefaultRouteSentinel(t *testing.T) {
	c := Default()
	c.Mode = ModeOff
	c.Hosts["/"] = HostOverride{Mode: ModeBlock}
	c.InvertFailureHosts = []string{"/"}
	ex := validException(time.Now().UTC())
	ex.Host = "/"
	c.Exceptions = []Exception{ex}
	if err := c.Validate(); err != nil {
		t.Fatalf("default route sentinel rejected: %v", err)
	}
	e := c.Effective("unknown.test", "/")
	if e.Key != "/" || e.Mode != ModeBlock || !e.FailClosed {
		t.Fatalf("root override/inversion not applied: %+v", e)
	}
	e = c.Effective("known.test", "known.test")
	if e.Mode != ModeOff || e.FailClosed {
		t.Fatalf("root policy leaked to host route: %+v", e)
	}
	if !ex.Matches("unknown.test", "/", "POST", "/search", ex.CreatedAt) || ex.Matches("known.test", "known.test", "POST", "/search", ex.CreatedAt) {
		t.Fatal("root exception scope leaked")
	}
}

func TestRouteSentinelDoesNotAcceptPaths(t *testing.T) {
	for _, key := range []string{"/api", "//", "a/b", "\\", "/ ", "/?x"} {
		if ValidKey(key) {
			t.Errorf("arbitrary path key accepted: %q", key)
		}
		c := Default()
		c.Hosts[key] = HostOverride{Mode: ModeBlock}
		if c.Validate() == nil {
			t.Errorf("invalid host key accepted: %q", key)
		}
		c = Default()
		c.InvertFailureHosts = []string{key}
		if c.Validate() == nil {
			t.Errorf("invalid failure key accepted: %q", key)
		}
	}
}
