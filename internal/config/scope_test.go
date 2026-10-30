package config

import (
	"testing"
	"time"
)

func TestExceptionRequiresPathScope(t *testing.T) {
	c := Default()
	e := validException(time.Now())
	e.Path = ""
	c.Exceptions = []Exception{e}
	if err := c.Validate(); err == nil {
		t.Fatal("host-wide exception without path accepted")
	}
}
