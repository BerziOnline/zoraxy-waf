package history

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func clock(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func TestWindowsAndCharts(t *testing.T) {
	loc := time.FixedZone("test", 2*3600)
	now := time.Date(2026, 10, 9, 10, 30, 0, 0, loc)
	dir := t.TempDir()
	s := New(dir, clock(&now))
	// Three attacks this hour, one allowed yesterday 23:00, one blocked 8 days ago.
	s.Record("blocked")
	s.Record("would_block")
	s.Record("blocked")
	past := time.Date(2026, 10, 8, 23, 10, 0, 0, loc)
	s.now = clock(&past)
	s.Record("allowed")
	old := now.AddDate(0, 0, -8)
	s.now = clock(&old)
	s.Record("blocked")
	s.now = clock(&now)
	sum := s.Summary(loc)
	if sum.Today.Attacks() != 3 || sum.Today.Allowed != 0 {
		t.Fatalf("today %+v", sum.Today)
	}
	if sum.Yesterday.Allowed != 1 || sum.Yesterday.Attacks() != 0 {
		t.Fatalf("yesterday %+v", sum.Yesterday)
	}
	if sum.H24.Total() != 4 || sum.D7.Total() != 4 || sum.D30.Total() != 5 {
		t.Fatalf("h24 %d d7 %d d30 %d", sum.H24.Total(), sum.D7.Total(), sum.D30.Total())
	}
	if len(sum.Hours) != 24 || len(sum.Days) != 30 {
		t.Fatalf("series %d/%d", len(sum.Hours), len(sum.Days))
	}
	if sum.Hours[23].Attacks() != 3 || sum.Hours[12].Allowed != 1 { // 23:00 yesterday = 11 h before 10:00 = index 23-11
		t.Fatalf("hours %+v %+v", sum.Hours[23], sum.Hours[12])
	}
	if sum.Days[29].Attacks() != 3 || sum.Days[28].Allowed != 1 || sum.Days[21].Blocked != 1 {
		t.Fatalf("days %+v %+v %+v", sum.Days[29], sum.Days[28], sum.Days[21])
	}
	if sum.DaysKnown != 8 {
		t.Fatalf("days known %d", sum.DaysKnown)
	}
}

func TestPersistAndPrune(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 10, 9, 10, 0, 0, 0, loc)
	dir := t.TempDir()
	s := New(dir, clock(&now))
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, fileName)); err == nil {
		t.Fatal("empty store must not write a file")
	}
	s.Record("blocked")
	ancient := now.AddDate(0, 0, -40)
	s.now = clock(&ancient)
	s.Record("allowed")
	s.now = clock(&now)
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, fileName+".tmp")); err == nil {
		t.Fatal("temp file left behind")
	}
	again := New(dir, clock(&now))
	sum := again.Summary(loc)
	if sum.D30.Blocked != 1 {
		t.Fatalf("reload lost data: %+v", sum.D30)
	}
	again.mu.Lock()
	n := len(again.buckets)
	again.mu.Unlock()
	if n != 1 {
		t.Fatalf("40-day-old bucket must be pruned, have %d buckets", n)
	}
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if New(dir, clock(&now)).Summary(loc).D30.Total() != 0 {
		t.Fatal("broken file must start empty, not fail")
	}
}

func TestUnknownActionIgnored(t *testing.T) {
	now := time.Now()
	s := New(t.TempDir(), clock(&now))
	s.Record("nonsense")
	if s.Summary(time.UTC).H24.Total() != 0 || s.dirty {
		t.Fatal("unknown action must not count or dirty the store")
	}
}
