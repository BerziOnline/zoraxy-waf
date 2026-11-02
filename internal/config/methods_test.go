package config

import (
	"testing"
	"time"
)

func TestHostMethodsValidationAndEffective(t *testing.T) {
	for m, ok := range map[string]bool{"PUT": true, "PATCH": true, "DELETE": true, "PROPFIND": true, "VERSION-CONTROL": true,
		"GET": false, "POST": false, "TRACE": false, "CONNECT": false, "patch": false, "PU": false, "PUT1": false} {
		if ValidMethod(m) != ok {
			t.Errorf("ValidMethod(%q) = %v", m, !ok)
		}
	}
	c := Default()
	c.Hosts["mm.example"] = HostOverride{Mode: ModeInherit, Methods: []string{"PUT", "PATCH"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	e := c.Effective("MM.Example:443", "")
	if !e.AllowsMethod("PATCH") || !e.AllowsMethod("GET") || e.AllowsMethod("DELETE") {
		t.Fatalf("effective methods: %+v", e.Methods)
	}
	if o := c.Effective("shop.example", ""); o.AllowsMethod("PUT") || !o.AllowsMethod("OPTIONS") {
		t.Fatal("other host must keep the CRS default only")
	}
	d := c.Clone()
	d.Hosts["mm.example"].Methods[0] = "DELETE"
	if c.Hosts["mm.example"].Methods[0] != "PUT" {
		t.Fatal("Clone shares the methods slice")
	}
	c.Hosts["mm.example"] = HostOverride{Mode: ModeInherit, Methods: []string{"PUT", "PUT"}}
	if c.Validate() == nil {
		t.Fatal("duplicate method accepted")
	}
}

func TestLearnModeSetupAndWirePolicy(t *testing.T) {
	c := Default()
	if !c.SetupRequired() || c.Learning.Days != DefaultLearningDays {
		t.Fatalf("fresh default: %+v", c.Learning)
	}
	c.Hosts["a.example"] = HostOverride{Mode: ModeInherit}
	if !c.SetupRequired() {
		t.Fatal("an inherit override is not an activation")
	}
	c.Hosts["a.example"] = HostOverride{Mode: ModeLearn}
	if c.SetupRequired() {
		t.Fatal("a learning host is switched on")
	}
	c.Mode = ModeLearn
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	p := c.Policy()
	if p.Mode != ModeReport || p.Hosts["a.example"].Mode != ModeReport {
		t.Fatalf("core policy must see learning as report: %+v", p)
	}
	c.Learning.Days = 0
	if c.Validate() == nil {
		t.Fatal("0 learning days accepted")
	}
	c.Learning.Days = MaxLearningDays + 1
	if c.Validate() == nil {
		t.Fatal("too many learning days accepted")
	}
	d := Default()
	d.Learning.ActivatedAt = time.Now()
	if d.SetupRequired() {
		t.Fatal("activated install switched off must not ask for setup again")
	}
}
