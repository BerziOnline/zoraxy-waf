package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultIsOffCorazaPL1AndValid(t *testing.T) {
	c := Default()
	if c.Mode != ModeOff || c.Engine != EngineCoraza || c.Coraza.ParanoiaLevel != 1 {
		t.Fatalf("unexpected defaults %+v", c)
	}
	if c.MaxBodyKB != 64 || c.BodyTimeoutMS != 5000 || c.Coraza.AnomalyThreshold != 5 {
		t.Fatalf("unexpected limit defaults %+v", c)
	}
	if c.GCTarget != 400 {
		t.Fatalf("speed (gc_target) must default to 400, got %d", c.GCTarget)
	}
	for _, v := range []int{0, 50, 300, 1600, -1} {
		bad := c
		bad.GCTarget = v
		if bad.Validate() == nil {
			t.Fatalf("gc_target %d accepted", v)
		}
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func validException(now time.Time) Exception {
	return Exception{ID: "x1", RuleID: 942100, Host: "shop.example", Method: "POST", Path: "/search",
		Argument: "q", Reason: "search box false positive", CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
}

func TestValidateRejects(t *testing.T) {
	now := time.Now().UTC()
	mut := map[string]func(c *Config){
		"engine":              func(c *Config) { c.Engine = "modsec" },
		"mode":                func(c *Config) { c.Mode = "learn" },
		"body kb low":         func(c *Config) { c.MaxBodyKB = 0 },
		"body kb high":        func(c *Config) { c.MaxBodyKB = 1025 },
		"timeout low":         func(c *Config) { c.BodyTimeoutMS = 99 },
		"timeout high":        func(c *Config) { c.BodyTimeoutMS = 30001 },
		"pl 0":                func(c *Config) { c.Coraza.ParanoiaLevel = 0 },
		"pl 5":                func(c *Config) { c.Coraza.ParanoiaLevel = 5 },
		"threshold":           func(c *Config) { c.Coraza.AnomalyThreshold = 0 },
		"host mode":           func(c *Config) { c.Hosts = map[string]HostOverride{"a.example": {Mode: "learn"}} },
		"host key upper":      func(c *Config) { c.Hosts = map[string]HostOverride{"A.example": {Mode: ModeBlock}} },
		"host key space":      func(c *Config) { c.Hosts = map[string]HostOverride{"a example": {Mode: ModeBlock}} },
		"host body":           func(c *Config) { c.Hosts = map[string]HostOverride{"a.example": {Mode: ModeBlock, MaxBodyKB: 2048}} },
		"host timeout":        func(c *Config) { c.Hosts = map[string]HostOverride{"a.example": {Mode: ModeBlock, BodyTimeoutMS: 50}} },
		"host pl":             func(c *Config) { c.Hosts = map[string]HostOverride{"a.example": {Mode: ModeBlock, ParanoiaLevel: 7}} },
		"inversion empty":     func(c *Config) { c.InvertFailureHosts = []string{""} },
		"inversion pattern":   func(c *Config) { c.InvertFailureHosts = []string{"a.example b.example"} },
		"exception no host":   func(c *Config) { e := validException(now); e.Host = ""; c.Exceptions = []Exception{e} },
		"exception no reason": func(c *Config) { e := validException(now); e.Reason = ""; c.Exceptions = []Exception{e} },
		"exception rule":      func(c *Config) { e := validException(now); e.RuleID = 0; c.Exceptions = []Exception{e} },
		"exception path":      func(c *Config) { e := validException(now); e.Path = "search"; c.Exceptions = []Exception{e} },
		"exception method":    func(c *Config) { e := validException(now); e.Method = "get"; c.Exceptions = []Exception{e} },
		"exception expiry":    func(c *Config) { e := validException(now); e.ExpiresAt = time.Time{}; c.Exceptions = []Exception{e} },
		"exception too long": func(c *Config) {
			e := validException(now)
			e.ExpiresAt = now.Add(400 * 24 * time.Hour)
			c.Exceptions = []Exception{e}
		},
		"exception dup id": func(c *Config) {
			c.Exceptions = []Exception{validException(now), validException(now)}
		},
		"crowdsec no url": func(c *Config) { c.Engine = EngineCrowdSec; c.CrowdSec.APIKey = "k" },
		"crowdsec no key": func(c *Config) { c.Engine = EngineCrowdSec; c.CrowdSec.URL = "http://127.0.0.1:7422/" },
		"crowdsec remote http": func(c *Config) {
			c.Engine = EngineCrowdSec
			c.CrowdSec = CrowdSecSettings{URL: "http://crowdsec.example:7422/", APIKey: "k", TimeoutMS: 200}
		},
		"crowdsec localhost name http": func(c *Config) {
			c.Engine = EngineCrowdSec
			c.CrowdSec = CrowdSecSettings{URL: "http://localhost:7422/", APIKey: "k", TimeoutMS: 200}
		},
		"crowdsec userinfo": func(c *Config) {
			c.Engine = EngineCrowdSec
			c.CrowdSec = CrowdSecSettings{URL: "https://u:p@crowdsec.example/", APIKey: "k", TimeoutMS: 200}
		},
		"crowdsec scheme": func(c *Config) {
			c.Engine = EngineCrowdSec
			c.CrowdSec = CrowdSecSettings{URL: "ftp://127.0.0.1/", APIKey: "k", TimeoutMS: 200}
		},
		"crowdsec timeout": func(c *Config) {
			c.Engine = EngineCrowdSec
			c.CrowdSec = CrowdSecSettings{URL: "http://127.0.0.1:7422/", APIKey: "k", TimeoutMS: 99999}
		},
		"concurrency": func(c *Config) { c.MaxConcurrent = 0 },
		"ring":        func(c *Config) { c.Events.RingSize = 5 },
	}
	for name, m := range mut {
		c := Default()
		m(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestValidateAcceptsCrowdSecLoopbackHTTPAndRemoteTLS(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:7422/", "http://[::1]:7422/", "https://crowdsec.example:7422/"} {
		c := Default()
		c.Engine = EngineCrowdSec
		c.CrowdSec = CrowdSecSettings{URL: u, APIKey: "secret", TimeoutMS: 200}
		if err := c.Validate(); err != nil {
			t.Errorf("%s rejected: %v", u, err)
		}
	}
}

func TestEffectiveHostRouteIDPrecedenceAndInheritance(t *testing.T) {
	c := Default()
	c.Mode = ModeReport
	c.FailClosed = false
	c.InvertFailureHosts = []string{"bank.example"}
	c.Hosts = map[string]HostOverride{
		"shop.example":   {Mode: ModeBlock, MaxBodyKB: 256, ParanoiaLevel: 2},
		"*.apps.example": {Mode: ModeOff},
		"blog.example":   {Mode: ModeInherit},
	}
	e := c.Effective("Shop.Example:443", "")
	if e.Mode != ModeBlock || e.MaxBodyKB != 256 || e.ParanoiaLevel != 2 || e.BodyTimeoutMS != 5000 || e.Key != "shop.example" {
		t.Fatalf("host override not applied: %+v", e)
	}
	// route_id takes precedence over the host header
	e = c.Effective("x.apps.example", "*.apps.example")
	if e.Mode != ModeOff || e.Key != "*.apps.example" {
		t.Fatalf("route id precedence: %+v", e)
	}
	e = c.Effective("blog.example", "")
	if e.Mode != ModeReport || e.ParanoiaLevel != 1 {
		t.Fatalf("inherit: %+v", e)
	}
	e = c.Effective("bank.example", "")
	if !e.FailClosed {
		t.Fatalf("inversion should flip fail-open to fail-closed: %+v", e)
	}
	e = c.Effective("unknown.example.", "")
	if e.Mode != ModeReport || e.Key != "unknown.example" || e.FailClosed {
		t.Fatalf("default: %+v", e)
	}
}

func TestPolicyMatchesContract(t *testing.T) {
	c := Default()
	c.Mode = ModeReport
	c.InvertFailureHosts = []string{"bank.example"}
	c.Hosts = map[string]HostOverride{"shop.example": {Mode: ModeBlock, MaxBodyKB: 128, ParanoiaLevel: 3}}
	b, _ := json.Marshal(c.Policy())
	want := `{"mode":"report","fail_closed":false,"invert_failure_hosts":["bank.example"],"max_body_kb":64,"body_timeout_ms":5000,"hosts":{"shop.example":{"mode":"block","max_body_kb":128}}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
}

func TestExceptionScopeAndExpiry(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	ex := validException(now)
	ex.Path = "/api/*"
	ex.Method = ""
	if !ex.Matches("shop.example", "", "GET", "/api/items", now) {
		t.Fatal("prefix/any-method should match")
	}
	if ex.Matches("other.example", "", "GET", "/api/items", now) {
		t.Fatal("other host must not match")
	}
	if ex.Matches("shop.example", "", "GET", "/apix", now) {
		t.Fatal("prefix must respect path")
	}
	if !ex.Matches("alias.example", "shop.example", "GET", "/api/x", now) {
		t.Fatal("route id should match")
	}
	if ex.Matches("shop.example", "", "GET", "/api/items", now.Add(25*time.Hour)) {
		t.Fatal("expired exception must not match")
	}
	ex.Path = "/search"
	ex.Method = "POST"
	if ex.Matches("shop.example", "", "GET", "/search", now) || ex.Matches("shop.example", "", "POST", "/search/x", now) {
		t.Fatal("exact path/method scope violated")
	}
	if !ex.Matches("shop.example:8443", "", "POST", "/search", now) {
		t.Fatal("host with port should canonicalize")
	}
}

func TestCloneIsDeep(t *testing.T) {
	c := Default()
	c.Hosts = map[string]HostOverride{"a.example": {Mode: ModeBlock}}
	c.InvertFailureHosts = []string{"a.example"}
	c.Exceptions = []Exception{validException(time.Now())}
	d := c.Clone()
	d.Hosts["b.example"] = HostOverride{Mode: ModeOff}
	d.InvertFailureHosts[0] = "z.example"
	d.Exceptions[0].Reason = "changed"
	if len(c.Hosts) != 1 || c.InvertFailureHosts[0] != "a.example" || c.Exceptions[0].Reason == "changed" {
		t.Fatal("clone shares state")
	}
}

func TestStoreSaveLoadAtomic0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "config.json")
	c := Default()
	c.Mode = ModeBlock
	c.CrowdSec = CrowdSecSettings{URL: "http://127.0.0.1:7422/", APIKey: "very-secret", TimeoutMS: 200}
	if err := Save(path, c); err != nil {
		t.Fatalf("save: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode: %v %v", st.Mode(), err)
	}
	dst, _ := os.Stat(filepath.Dir(path))
	if dst.Mode().Perm()&0o077 != 0 {
		t.Fatalf("config dir too open: %v", dst.Mode())
	}
	got, err := Load(path)
	if err != nil || got.Mode != ModeBlock || got.CrowdSec.APIKey != "very-secret" {
		t.Fatalf("load: %+v %v", got, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestLoadMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(filepath.Join(dir, "none.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file should report ErrNotExist, got %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"mode":"block",`), 0o600)
	if _, err := Load(bad); err == nil {
		t.Fatal("corrupt config accepted")
	}
	invalid := filepath.Join(dir, "invalid.json")
	os.WriteFile(invalid, []byte(`{"schema_version":1,"engine":"coraza","mode":"chaos"}`), 0o600)
	if _, err := Load(invalid); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("invalid config accepted: %v", err)
	}
}

func TestSaveFailureLeavesOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c := Default()
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	c.Mode = "nonsense"
	if err := Save(path, c); err == nil {
		t.Fatal("invalid config persisted")
	}
	got, err := Load(path)
	if err != nil || got.Mode != ModeOff {
		t.Fatalf("old config not retained: %+v %v", got, err)
	}
}
