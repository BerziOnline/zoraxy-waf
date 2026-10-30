package service

import (
	"testing"
	"time"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
)

func TestCloseWaitsForInflightInspectionAndFlushesItsEvent(t *testing.T) {
	fe := &fakeEngine{block: make(chan struct{}), started: make(chan struct{}, 1), decision: engine.Decision{Interrupted: true, Status: 403}}
	s := newSvc(t, Options{Build: func(config.Config) (engine.Engine, error) { return fe, nil }})
	setMode(t, s, config.ModeBlock)
	inspected := make(chan struct{})
	go func() { defer close(inspected); callInspect(t, s, payload("GET", "/", "")) }()
	<-fe.started
	stopped := make(chan struct{})
	go func() { s.Close(); close(stopped) }()
	early := false
	select {
	case <-stopped:
		early = true
	case <-time.After(30 * time.Millisecond):
	}
	close(fe.block)
	<-inspected
	<-stopped
	if early {
		t.Fatal("Close returned before in-flight inspection/event completed")
	}
	if !fe.closed.Load() || s.Events().Stats().Written != 1 {
		t.Fatal("shutdown did not close engine and flush final event")
	}
}
