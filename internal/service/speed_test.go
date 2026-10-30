package service

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
)

// fakeGC mimics runtime/debug.SetGCPercent: it stores the target and returns
// the previous one.
type fakeGC struct {
	mu    sync.Mutex
	value int
	calls int
}

func (f *fakeGC) set(v int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	old := f.value
	f.value = v
	return old
}
func (f *fakeGC) get() int { f.mu.Lock(); defer f.mu.Unlock(); return f.value }

func TestGCControlAppliesChosenTarget(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start int
		want  map[int]int // chosen target -> active target
	}{
		{"default GOGC", 100, map[int]int{100: 100, 200: 200, 400: 400, 800: 800}},
		{"operator GOGC is replaced by the admin choice", 800, map[int]int{100: 100, 400: 400}},
		{"GOGC=off stays off", -1, map[int]int{100: -1, 400: -1, 800: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeGC{value: tc.start}
			g := newGCControl(f.set)
			for _, target := range config.GCTargets {
				want, ok := tc.want[target]
				if !ok {
					continue
				}
				if got := g.apply(target); got != want || f.get() != want {
					t.Fatalf("choose %d: active %d, runtime %d, want %d", target, got, f.get(), want)
				}
				calls := f.calls
				g.apply(target)
				if f.calls != calls {
					t.Fatal("repeated apply with unchanged setting touched the runtime")
				}
			}
			if g.start() != tc.start {
				t.Fatalf("start value %d, want %d", g.start(), tc.start)
			}
		})
	}
}

func TestGCTargetFollowsAppliedAndPersistedConfig(t *testing.T) {
	dir := t.TempDir()
	f := &fakeGC{value: 100}
	build := func(config.Config) (engine.Engine, error) { return &fakeEngine{}, nil }
	s := newSvc(t, Options{DataDir: dir, Build: build, SetGCPercent: f.set})
	if s.Current().GCTarget != config.DefaultGCTarget || s.GCPercent() != 400 || f.get() != 400 {
		t.Fatalf("default must be 400 at start: config %d active %d runtime %d", s.Current().GCTarget, s.GCPercent(), f.get())
	}
	setMode(t, s, "block", func(c *config.Config) { c.GCTarget = 200 })
	if s.GCPercent() != 200 || f.get() != 200 {
		t.Fatalf("200 not applied at runtime: active %d runtime %d", s.GCPercent(), f.get())
	}
	// A rejected save must not change the GC target.
	for _, bad := range []func(*config.Config){
		func(c *config.Config) { c.GCTarget = 800; c.MaxBodyKB = 0 },
		func(c *config.Config) { c.GCTarget = 300 },
	} {
		if _, err := s.Apply(func(c *config.Config) error { bad(c); return nil }); err == nil {
			t.Fatal("invalid config accepted")
		}
		if f.get() != 200 {
			t.Fatal("rejected save changed GC target")
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if want := `"gc_target": 200`; !strings.Contains(string(data), want) {
		t.Fatalf("gc_target not persisted: %s", data)
	}
	// Restart: a new service reads the stored setting and applies it at start.
	s.Close()
	f2 := &fakeGC{value: 100}
	s2 := newSvc(t, Options{DataDir: dir, Build: build, SetGCPercent: f2.set})
	if s2.Current().GCTarget != 200 || f2.get() != 200 {
		t.Fatalf("restart lost gc_target: config %d runtime %d", s2.Current().GCTarget, f2.get())
	}
	setMode(t, s2, "block", func(c *config.Config) { c.GCTarget = 100 })
	if f2.get() != 100 || s2.GCPercent() != 100 {
		t.Fatalf("choosing 100 not applied: runtime %d", f2.get())
	}
}

func TestGCTargetRealRuntimeSetting(t *testing.T) {
	// Real runtime/debug path: exactly what the plugin process does in production.
	start := debug.SetGCPercent(100)
	t.Cleanup(func() { debug.SetGCPercent(start) })
	g := newGCControl(debug.SetGCPercent)
	// Each step reads the value back without leaving a trace (-1 does not
	// collect) and restores it, so a no-op apply fails at every step.
	for _, target := range []int{400, 800, 200, 100} {
		g.apply(target)
		got := debug.SetGCPercent(-1)
		debug.SetGCPercent(got)
		if got != target {
			t.Fatalf("runtime GC target %d after choosing %d", got, target)
		}
	}
}
