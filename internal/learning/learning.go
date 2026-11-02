// Package learning keeps what the WAF observed per host while it learns:
// when the host's learning period started, how many requests were checked,
// and which rules would have blocked which requests ("findings").
//
// Findings decide whether a host may switch to blocking. A finding made on a
// request that carried a login (cookie, Authorization or a token header) is
// most likely a real user of the service and therefore "open": it keeps the
// host learning until it is resolved (method allowed, exception added) or
// marked as an attack. Findings without a login are most likely scanners and
// do not hold the host back. Only header names are used, never values.
package learning

import (
	"encoding/json"
	"errors"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"zoraxy-waf-plugin/internal/events"
)

const (
	fileName = "learning.json"
	// Bounds keep the file small even under a scanner flood.
	maxHosts             = 1000
	maxFindingsPerHost   = 200
	maxClientsPerFinding = 32
	maxRulesPerFinding   = 16
)

// Rule is one detection rule of a finding, with the argument it fired on
// when it was a single request argument.
type Rule struct {
	ID       int    `json:"id"`
	Message  string `json:"message,omitempty"`
	Argument string `json:"argument,omitempty"`
}

// Finding is one kind of request on a host that rules would have blocked:
// same method, same path pattern. One request that trips four XSS rules is
// one finding with four rules, not four findings.
type Finding struct {
	Method    string    `json:"method"`
	Path      string    `json:"path"`    // pattern: ID-like path segments shown as *
	Example   string    `json:"example"` // newest concrete path
	Rules     []Rule    `json:"rules"`
	Count     int       `json:"count"`
	WithLogin int       `json:"with_login"`        // requests that carried a login
	Clients   []uint64  `json:"clients,omitempty"` // hashed client IPs (distinct, capped)
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	EventID   string    `json:"event_id,omitempty"`  // newest event
	Dismissed bool      `json:"dismissed,omitempty"` // operator marked it as an attack
}

// HasRule reports whether the finding contains rule id.
func (f *Finding) HasRule(id int) bool {
	for _, r := range f.Rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

// Host is the learning record of one host.
type Host struct {
	Since    time.Time `json:"since"`             // first request while learning
	Requests uint64    `json:"requests"`          // requests checked while learning
	Dropped  int       `json:"dropped,omitempty"` // findings not kept (cap)
	// DroppedLogin counts findings with a login that could not be kept (cap
	// reached with nothing to evict). They hold the host like open findings:
	// incomplete evidence must never let a host switch to blocking.
	DroppedLogin int                 `json:"dropped_login,omitempty"`
	Findings     map[string]*Finding `json:"findings"`
	// Paths counts login-bearing traffic only, without query values or bodies.
	Paths map[string]int `json:"paths,omitempty"`
}

// Store is safe for concurrent use. Observe runs once per checked request
// in learning mode and does not allocate for a known host.
type Store struct {
	flushMu sync.Mutex // one writer at a time, snapshot and write together
	mu      sync.Mutex
	path    string
	hosts   map[string]*Host
	dirty   bool
	loadErr string
}

// Open loads the learning record from dir. A damaged file is kept aside
// (learning.json.broken) and learning starts over; the reason is reported.
func Open(dir string) *Store {
	s := &Store{path: filepath.Join(dir, fileName), hosts: map[string]*Host{}}
	// A write interrupted by a plugin stop (Zoraxy disables plugins without
	// waiting) leaves its temp file behind; the record itself stays intact
	// because only a finished temp file is renamed over it.
	if stale, err := filepath.Glob(filepath.Join(dir, fileName+".*.tmp")); err == nil {
		for _, f := range stale {
			_ = os.Remove(f)
		}
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.loadErr = "learning record unreadable; learning starts over"
		}
		return s
	}
	var hosts map[string]*Host
	if err := json.Unmarshal(b, &hosts); err != nil {
		_ = os.Rename(s.path, s.path+".broken")
		s.loadErr = "learning record damaged (kept as learning.json.broken); learning starts over"
		return s
	}
	for k, h := range hosts {
		if h == nil {
			continue
		}
		if h.Findings == nil {
			h.Findings = map[string]*Finding{}
		}
		s.hosts[k] = h
	}
	return s
}

// LoadError is empty unless the stored record could not be used.
func (s *Store) LoadError() string { s.mu.Lock(); defer s.mu.Unlock(); return s.loadErr }

func (s *Store) host(key string, now time.Time) *Host {
	h := s.hosts[key]
	if h == nil {
		if len(s.hosts) >= maxHosts {
			return nil
		}
		h = &Host{Findings: map[string]*Finding{}}
		s.hosts[key] = h
	}
	if h.Since.IsZero() {
		h.Since = now
	}
	return h
}

// Observe counts one checked request of a learning host; the first one
// starts the host's learning period.
func (s *Store) Observe(key string, now time.Time) {
	s.mu.Lock()
	if h := s.host(key, now); h != nil {
		h.Requests++
		s.dirty = true
	}
	s.mu.Unlock()
}

// ObservePath records repeated login-bearing path patterns, capped per host.
func (s *Store) ObservePath(key, path string, login bool, now time.Time) {
	if !login || len(path) > 1024 || !strings.HasPrefix(path, "/") {
		return
	}
	path = Pattern(strings.SplitN(path, "?", 2)[0])
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.host(key, now)
	if h == nil {
		return
	}
	if h.Paths == nil {
		h.Paths = map[string]int{}
	}
	if h.Paths[path] == 0 && len(h.Paths) >= 200 {
		return
	}
	if h.Paths[path] < 1000000 {
		h.Paths[path]++
	}
	s.dirty = true
}

// Record adds a would-block event to the host's findings. login says
// whether the request carried a login (computed from all original header
// names, see WithLoginHeader). Scoring and correlation rules are skipped
// (same as exception suggestions).
func (s *Store) Record(key string, ev events.Event, login bool) {
	sugg := events.Suggest(ev)
	if len(sugg) == 0 {
		return
	}
	client := hashIP(ev.ClientIP)
	msg := map[int]string{}
	for _, m := range ev.Matches {
		if msg[m.RuleID] == "" {
			msg[m.RuleID] = m.Message
		}
	}
	pattern := Pattern(ev.Path)
	k := FindingKey(ev.Method, pattern)
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.host(key, ev.Time)
	if h == nil {
		return
	}
	f := h.Findings[k]
	if f == nil {
		if len(h.Findings) >= maxFindingsPerHost && !(login && evictScanner(h)) {
			h.Dropped++
			if login {
				h.DroppedLogin++
			}
			s.dirty = true
			return
		}
		f = &Finding{Method: ev.Method, Path: pattern, FirstSeen: ev.Time, Rules: []Rule{}}
		h.Findings[k] = f
	}
	for _, sg := range sugg {
		known := false
		for i, r := range f.Rules {
			if r.ID == sg.RuleID && r.Argument == sg.Argument {
				f.Rules[i].Message = clip(msg[sg.RuleID], 200)
				known = true
			}
		}
		if !known {
			if len(f.Rules) < maxRulesPerFinding {
				f.Rules = append(f.Rules, Rule{ID: sg.RuleID, Message: clip(msg[sg.RuleID], 200), Argument: sg.Argument})
			} else if login {
				h.DroppedLogin++ // a rule of a login finding is missing from the evidence
			}
		}
	}
	f.Count++
	if login {
		f.WithLogin++
	}
	f.Example = ev.Path
	f.LastSeen = ev.Time
	f.EventID = ev.ID
	if client != 0 && len(f.Clients) < maxClientsPerFinding && !contains(f.Clients, client) {
		f.Clients = append(f.Clients, client)
	}
	s.dirty = true
}

// Hosts lists the hosts with a record (no copy of the findings).
func (s *Store) Hosts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.hosts))
	for k := range s.hosts {
		out = append(out, k)
	}
	return out
}

// Snapshot returns a deep copy of all host records.
func (s *Store) Snapshot() map[string]Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Host, len(s.hosts))
	for k, h := range s.hosts {
		c := *h
		c.Paths = make(map[string]int, len(h.Paths))
		for p, n := range h.Paths {
			c.Paths[p] = n
		}
		c.Findings = make(map[string]*Finding, len(h.Findings))
		for fk, f := range h.Findings {
			fc := *f
			fc.Clients = append([]uint64(nil), f.Clients...)
			fc.Rules = append([]Rule(nil), f.Rules...)
			c.Findings[fk] = &fc
		}
		out[k] = c
	}
	return out
}

// Reset forgets one host: its next request starts a new learning period.
func (s *Store) Reset(key string) {
	s.mu.Lock()
	if _, ok := s.hosts[key]; ok {
		delete(s.hosts, key)
		s.dirty = true
	}
	s.mu.Unlock()
}

// RestartPeriod starts a fresh learning period for a host (counted from its
// next request) and keeps its findings: what a host recorded in report mode
// is real evidence and must hold it until resolved.
func (s *Store) RestartPeriod(key string) {
	s.mu.Lock()
	if h, ok := s.hosts[key]; ok {
		h.Since, h.Requests = time.Time{}, 0
		s.dirty = true
	}
	s.mu.Unlock()
}

// Take copies the records of the given hosts (all hosts if all is true) so
// a reset can be undone when the save it belongs to fails.
func (s *Store) Take(all bool, hosts []string) map[string]*Host {
	snap := s.Snapshot()
	out := map[string]*Host{}
	if all {
		for k, h := range snap {
			hc := h
			out[k] = &hc
		}
		return out
	}
	for _, k := range hosts {
		if h, ok := snap[k]; ok {
			hc := h
			out[k] = &hc
		} else {
			out[k] = nil // had no record: undo removes a new one
		}
	}
	return out
}

// Restore puts records taken with Take back (nil entries are removed).
// all: hosts not in prev are removed too (undo of ResetAll).
func (s *Store) Restore(prev map[string]*Host, all bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if all {
		s.hosts = map[string]*Host{}
	}
	for k, h := range prev {
		if h == nil {
			delete(s.hosts, k)
		} else {
			s.hosts[k] = h
		}
	}
	s.dirty = true
}

// ResetAll forgets every host (fresh activation).
func (s *Store) ResetAll() {
	s.mu.Lock()
	s.hosts = map[string]*Host{}
	s.dirty = true
	s.mu.Unlock()
}

// Dismiss marks a finding as an attack (true) or reopens it (false).
func (s *Store) Dismiss(key, finding string, dismissed bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.hosts[key]
	if h == nil || h.Findings[finding] == nil {
		return errors.New("finding not found")
	}
	h.Findings[finding].Dismissed = dismissed
	s.dirty = true
	return nil
}

// Flush writes the record when something changed: one writer at a time,
// unique temporary file, fsync, then rename, so a newer state is never
// overwritten by an older one and a crash leaves the old or the new file.
func (s *Store) Flush() error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(s.hosts)
	s.dirty = false
	s.mu.Unlock()
	if err == nil {
		err = writeAtomic(s.path, b)
	}
	if err != nil {
		s.markDirty()
	}
	return err
}

func writeAtomic(path string, b []byte) error {
	// A fresh install has no data directory before the first save.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	// The rename is durable only after the directory is synced.
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		err = nil // filesystem without directory fsync
	}
	return err
}

func (s *Store) markDirty() { s.mu.Lock(); s.dirty = true; s.mu.Unlock() }

// FindingKey identifies a finding within a host.
func FindingKey(method, pattern string) string { return method + " " + pattern }

// evictScanner removes the oldest finding without a login (a probable
// scanner, not marked) to make room for a finding with a login.
func evictScanner(h *Host) bool {
	victim := ""
	for k, f := range h.Findings {
		if f.WithLogin == 0 && !f.Dismissed && (victim == "" || f.LastSeen.Before(h.Findings[victim].LastSeen)) {
			victim = k
		}
	}
	if victim == "" {
		return false
	}
	delete(h.Findings, victim)
	h.Dropped++
	return true
}

// WithLoginHeader is WithLogin over a request's header map.
func WithLoginHeader(h map[string][]string) bool {
	for k := range h {
		if WithLogin([]string{k}) {
			return true
		}
	}
	return false
}

// WithLogin reports whether a request carried a login or session: Cookie,
// Authorization, or a header named like a token/session/API key. Real users
// of apps send one; scanners almost never do. Names only, never values.
func WithLogin(headerNames []string) bool {
	for _, n := range headerNames {
		n = strings.ToLower(n)
		switch n {
		case "cookie", "authorization", "proxy-authorization":
			return true
		}
		if strings.Contains(n, "token") || strings.Contains(n, "session") || strings.Contains(n, "api-key") || strings.Contains(n, "apikey") {
			return true
		}
	}
	return false
}

// Pattern groups paths of one kind: segments that look like IDs (numbers,
// UUIDs, long random tokens, mixed letters+digits of 8+ characters) become *.
// "/api/v4/users/8f3k2m9q1x7d4b6p/preferences" -> "/api/v4/users/*/preferences".
func Pattern(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if idLike(p) {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, "/")
}

func idLike(seg string) bool {
	if seg == "" {
		return false
	}
	digits, letters, other := 0, 0, 0
	for _, c := range seg {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			letters++
		case c == '-' || c == '_':
		default:
			other++
		}
	}
	switch {
	case other > 0:
		return false // file names, encoded text
	case letters == 0:
		return digits > 0 // numeric id
	case len(seg) >= 16:
		return digits > 0 || len(seg) >= 24 // uuid, token
	default:
		return len(seg) >= 8 && digits >= 2 // short mixed id like ab12cd34
	}
}

func hashIP(ip string) uint64 {
	if ip == "" {
		return 0
	}
	h := fnv.New64a()
	h.Write([]byte(ip))
	return h.Sum64()
}

func contains(list []uint64, v uint64) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// SortedKeys returns the finding keys of h, newest first.
func SortedKeys(h Host) []string {
	keys := make([]string, 0, len(h.Findings))
	for k := range h.Findings {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := h.Findings[keys[i]], h.Findings[keys[j]]
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return keys[i] < keys[j]
	})
	return keys
}
