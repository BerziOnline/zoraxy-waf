package service

import (
	"runtime/debug"
	"sync"
)

// gcControl sets the Go GC target of this plugin process (admin setting
// "Speed", config gc_target). Zoraxy's own collector is a different process
// and cannot be changed from here. Measured effect: docs/PERFORMANCE.md §4.
type gcControl struct {
	mu       sync.Mutex
	set      func(int) int
	baseline int // GC target at plugin start (GOGC or 100), captured on first use
	known    bool
	current  int
}

// apply sets the configured GC target and returns the active value. The
// admin's choice wins over a GOGC start value, except GOGC=off: a collector an
// operator disabled on purpose is never re-enabled.
func (g *gcControl) apply(target int) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.known {
		// SetGCPercent returns the previous value; restore it immediately. -1 only
		// pauses collection for this instant and cannot trigger a collection.
		g.baseline = g.set(-1)
		g.set(g.baseline)
		g.known = true
		g.current = g.baseline
	}
	if g.baseline < 0 {
		target = g.baseline
	}
	if target != g.current {
		g.set(target)
		g.current = target
	}
	return g.current
}

func (g *gcControl) active() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.current
}

// start is the GC target the process was started with (-1 = GOGC=off).
func (g *gcControl) start() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.baseline
}

func newGCControl(set func(int) int) *gcControl {
	return &gcControl{set: set}
}

// processGC is shared by every Service in the process because the Go GC
// target is process-global.
var processGC = newGCControl(debug.SetGCPercent)
