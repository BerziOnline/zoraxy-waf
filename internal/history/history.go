// Package history keeps hourly decision counters for 30 days so the UI can show
// today / 24 h / 7 d / 30 d with a reference instead of lifetime counters that
// reset on every plugin restart. Memory: at most 31*24 buckets.
package history

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	keepHours = 31 * 24
	fileName  = "history.json"
)

// Counts are decisions per bucket. Field order matches the JSON on disk.
type Counts struct {
	Allowed    uint64 `json:"allowed"`
	Blocked    uint64 `json:"blocked"`
	WouldBlock uint64 `json:"would_block"`
	Error      uint64 `json:"error"`
	Oversize   uint64 `json:"oversize"`
}

func (c *Counts) add(o Counts) {
	c.Allowed += o.Allowed
	c.Blocked += o.Blocked
	c.WouldBlock += o.WouldBlock
	c.Error += o.Error
	c.Oversize += o.Oversize
}

// Attacks are decisions where the engine found an attack, regardless of mode.
func (c Counts) Attacks() uint64 { return c.Blocked + c.WouldBlock }

// Total is every inspected request in the bucket.
func (c Counts) Total() uint64 { return c.Allowed + c.Blocked + c.WouldBlock + c.Error + c.Oversize }

type bucket struct {
	T int64 `json:"t"` // unix hour start
	Counts
}

type file struct {
	Version int      `json:"version"`
	Hours   []bucket `json:"hours"`
}

// Point is one chart bar: the bucket start and its counts.
type Point struct {
	Time time.Time `json:"time"`
	Counts
}

// Summary is what the UI needs for anchors and charts.
type Summary struct {
	Today     Counts  `json:"today"`      // since local midnight
	Yesterday Counts  `json:"yesterday"`  // full previous local day
	H24       Counts  `json:"h24"`        // last 24 hours
	D7        Counts  `json:"d7"`         // last 7 days incl. today
	D30       Counts  `json:"d30"`        // last 30 days incl. today
	Hours     []Point `json:"hours"`      // 24 hourly bars, oldest first
	Days      []Point `json:"days"`       // 30 daily bars, oldest first
	Since     string  `json:"since"`      // first bucket on record, RFC3339, "" when empty
	DaysKnown int     `json:"days_known"` // complete local days with data, caps the 7-day average
}

// Store is safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	path    string
	now     func() time.Time
	buckets map[int64]*Counts
	dirty   bool
}

// New loads <dir>/history.json; a missing or unreadable file starts empty (the
// WAF must never refuse to start because of statistics).
func New(dir string, now func() time.Time) *Store {
	s := &Store{path: filepath.Join(dir, fileName), now: now, buckets: map[int64]*Counts{}}
	if now == nil {
		s.now = time.Now
	}
	if b, err := os.ReadFile(s.path); err == nil {
		var f file
		if json.Unmarshal(b, &f) == nil && f.Version == 1 {
			for _, h := range f.Hours {
				c := h.Counts
				s.buckets[h.T] = &c
			}
		}
	}
	s.prune(s.now())
	return s
}

func hour(t time.Time) int64 { return t.Unix() - t.Unix()%3600 }

// Record counts one decision (events.Action* names) in the current hour.
func (s *Store) Record(action string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	h := hour(now)
	c := s.buckets[h]
	if c == nil {
		c = &Counts{}
		s.buckets[h] = c
		s.prune(now)
	}
	switch action {
	case "allowed":
		c.Allowed++
	case "blocked":
		c.Blocked++
	case "would_block":
		c.WouldBlock++
	case "error":
		c.Error++
	case "oversize":
		c.Oversize++
	default:
		return
	}
	s.dirty = true
}

func (s *Store) prune(now time.Time) {
	limit := hour(now) - keepHours*3600
	for t := range s.buckets {
		if t < limit {
			delete(s.buckets, t)
			s.dirty = true
		}
	}
}

// Flush writes the file when something changed. Atomic: temp file + rename.
func (s *Store) Flush() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	f := file{Version: 1}
	for t, c := range s.buckets {
		f.Hours = append(f.Hours, bucket{T: t, Counts: *c})
	}
	s.dirty = false
	s.mu.Unlock()
	sort.Slice(f.Hours, func(i, j int) bool { return f.Hours[i].T < f.Hours[j].T })
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Run flushes every interval until ctx is done, then once more.
func (s *Store) Run(done <-chan struct{}, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			s.Flush()
			return
		case <-t.C:
			s.Flush()
		}
	}
}

func (s *Store) sum(from, to time.Time) Counts {
	var c Counts
	a, b := hour(from), hour(to)
	for t, v := range s.buckets {
		if t >= a && t < b {
			c.add(*v)
		}
	}
	return c
}

// Summary computes the windows in loc (the operator's local time for "today").
func (s *Store) Summary(loc *time.Location) Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	if loc == nil {
		loc = time.Local
	}
	now := s.now().In(loc)
	next := now.Add(time.Hour) // include the running hour
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	out := Summary{
		Today:     s.sum(midnight, next),
		Yesterday: s.sum(midnight.AddDate(0, 0, -1), midnight),
		H24:       s.sum(now.Add(-23*time.Hour), next),
		D7:        s.sum(midnight.AddDate(0, 0, -6), next),
		D30:       s.sum(midnight.AddDate(0, 0, -29), next),
	}
	for i := 23; i >= 0; i-- {
		start := time.Unix(hour(now.Add(-time.Duration(i)*time.Hour)), 0).In(loc)
		out.Hours = append(out.Hours, Point{Time: start, Counts: s.sum(start, start.Add(time.Hour))})
	}
	for i := 29; i >= 0; i-- {
		start := midnight.AddDate(0, 0, -i)
		out.Days = append(out.Days, Point{Time: start, Counts: s.sum(start, start.AddDate(0, 0, 1))})
	}
	first := int64(0)
	for t := range s.buckets {
		if first == 0 || t < first {
			first = t
		}
	}
	if first > 0 {
		ft := time.Unix(first, 0).In(loc)
		out.Since = ft.Format(time.RFC3339)
		firstMidnight := time.Date(ft.Year(), ft.Month(), ft.Day(), 0, 0, 0, 0, loc)
		out.DaysKnown = int(midnight.Sub(firstMidnight).Hours() / 24)
		if out.DaysKnown > 30 {
			out.DaysKnown = 30
		}
	}
	return out
}

// ErrNoData marks an empty store for callers that want to distinguish it.
var ErrNoData = errors.New("no history")
