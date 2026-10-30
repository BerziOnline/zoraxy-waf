// Package events records redacted security events in a bounded in-memory
// ring and an asynchronous, size-capped, rotating JSONL file.
//
// Events never contain query/body/cookie/credential values: the query keeps
// parameter names only, headers keep names only (plus User-Agent and
// Content-Type), and rule messages are scrubbed of request values.
package events

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"zoraxy-waf-plugin/internal/engine"
)

const (
	ActionAllowed    = "allowed"
	ActionWouldBlock = "would_block"
	ActionBlocked    = "blocked"
	ActionError      = "error"
	ActionOversize   = "oversize"

	fileName = "events.jsonl"
	redacted = "[redacted]"
)

type Event struct {
	Version      int            `json:"v"`
	ID           string         `json:"id"`
	Time         time.Time      `json:"time"`
	RouteID      string         `json:"route_id,omitempty"`
	Host         string         `json:"host"`
	ClientIP     string         `json:"client_ip"`
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	Query        string         `json:"query,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	ContentType  string         `json:"content_type,omitempty"`
	HeaderNames  []string       `json:"header_names,omitempty"`
	Engine       string         `json:"engine"`
	RuleSet      string         `json:"rule_set,omitempty"`
	Revision     uint64         `json:"revision"`
	Mode         string         `json:"mode"`
	Paranoia     int            `json:"paranoia_level,omitempty"`
	Action       string         `json:"action"`
	Status       int            `json:"status,omitempty"`
	Coverage     string         `json:"coverage"`
	BodyBytes    int            `json:"body_bytes"`
	DurationMS   float64        `json:"duration_ms"`
	AnomalyScore int            `json:"anomaly_score,omitempty"`
	RuleDetails  bool           `json:"rule_details"`
	Matches      []engine.Match `json:"matches,omitempty"`
	Exceptions   []string       `json:"exceptions,omitempty"`
	Error        string         `json:"error,omitempty"`
}

// NewID returns a random 128-bit hex identifier.
func NewID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// FromRequest builds a redacted event skeleton for r.
func FromRequest(r *engine.Request, matches []engine.Match) Event {
	path, rawQuery, _ := strings.Cut(r.RawURI, "?")
	ev := Event{
		Version:  1,
		ID:       r.ID,
		Time:     time.Now().UTC(),
		RouteID:  clip(strings.ToLower(r.RouteID), 253),
		Host:     clip(canonicalHost(r.Host), 253),
		ClientIP: clip(r.ClientIP, 64),
		Method:   clip(r.Method, 16),
		Path:     clip(path, 1024),
		Query:    redactQuery(rawQuery),
	}
	names := make([]string, 0, len(r.Header))
	for k, v := range r.Header {
		names = append(names, clip(k, 64))
		switch strings.ToLower(k) {
		case "user-agent":
			if len(v) > 0 {
				ev.UserAgent = clip(v[0], 256)
			}
		case "content-type":
			if len(v) > 0 {
				ev.ContentType = clip(v[0], 128)
			}
		}
	}
	sort.Strings(names)
	if len(names) > 64 {
		names = names[:64]
	}
	ev.HeaderNames = names
	sc := newScrubber(r)
	for _, m := range matches {
		m.Message = clip(sc.scrub(m.Message), 512)
		ev.Matches = append(ev.Matches, m)
	}
	return ev
}

func canonicalHost(h string) string {
	h = strings.ToLower(h)
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.HasSuffix(h, "]") {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}

// redactQuery keeps parameter names and replaces every value.
func redactQuery(q string) string {
	if q == "" {
		return ""
	}
	parts := strings.Split(q, "&")
	if len(parts) > 64 {
		parts = parts[:64]
	}
	for i, p := range parts {
		k, _, hasValue := strings.Cut(p, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		k = clip(k, 64)
		if hasValue {
			parts[i] = k + "=" + redacted
		} else {
			parts[i] = k
		}
	}
	return clip(strings.Join(parts, "&"), 2048)
}

// scrubber removes request-supplied values from free text such as rule
// messages, which may embed matched data via macros.
type scrubber struct{ values []string }

func newScrubber(r *engine.Request) scrubber {
	var vals []string
	addQuery := func(raw string) {
		for _, p := range strings.Split(raw, "&") {
			_, v, _ := strings.Cut(p, "=")
			if dv, err := url.QueryUnescape(v); err == nil {
				vals = append(vals, dv)
			}
			vals = append(vals, v)
		}
	}
	if _, q, ok := strings.Cut(r.RawURI, "?"); ok {
		addQuery(q)
	}
	if len(r.Body) > 0 {
		addQuery(string(clipBytes(r.Body, 64*1024)))
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			vals = append(vals, v)
			if strings.EqualFold(k, "Cookie") {
				for _, c := range strings.Split(v, ";") {
					_, cv, _ := strings.Cut(c, "=")
					vals = append(vals, strings.TrimSpace(cv))
				}
			}
			if f := strings.Fields(v); len(f) == 2 {
				vals = append(vals, f[1]) // "Bearer <token>"
			}
		}
	}
	out := vals[:0]
	for _, v := range vals {
		if len(v) >= 4 {
			out = append(out, v)
		}
	}
	// Longest first so a value containing another is replaced whole.
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	if len(out) > 256 {
		out = out[:256]
	}
	return scrubber{values: out}
}

func clipBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func (s scrubber) scrub(msg string) string {
	for _, v := range s.values {
		if strings.Contains(msg, v) {
			msg = strings.ReplaceAll(msg, v, redacted)
		}
	}
	return msg
}

type Filter struct {
	Host     string
	Action   string
	RuleID   int
	ClientIP string
	Text     string
	Since    time.Time
	Limit    int
}

func (f Filter) match(ev *Event) bool {
	if f.Host != "" && ev.Host != f.Host && ev.RouteID != f.Host {
		return false
	}
	if f.Action != "" && ev.Action != f.Action {
		return false
	}
	if f.ClientIP != "" && ev.ClientIP != f.ClientIP {
		return false
	}
	if !f.Since.IsZero() && ev.Time.Before(f.Since) {
		return false
	}
	if f.RuleID != 0 {
		found := false
		for _, m := range ev.Matches {
			if m.RuleID == f.RuleID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.Text != "" {
		t := strings.ToLower(f.Text)
		hay := strings.ToLower(ev.Path + " " + ev.Error + " " + ev.UserAgent)
		for _, m := range ev.Matches {
			hay += " " + strings.ToLower(m.Message)
		}
		if !strings.Contains(hay, t) {
			return false
		}
	}
	return true
}

type Stats struct {
	Written     uint64 `json:"written"`
	Dropped     uint64 `json:"dropped"`
	WriteErrors uint64 `json:"write_errors"`
	Buffered    int    `json:"buffered"`
}

// Store is safe for concurrent use. Add never blocks on disk I/O.
type Store struct {
	mu   sync.RWMutex
	ring []Event
	next int
	full bool

	dir      string
	maxBytes int64
	maxFiles int
	queue    chan Event
	done     chan struct{}
	closed   atomic.Bool
	closeMu  sync.Mutex

	written, dropped, writeErrors atomic.Uint64
}

// NewStore creates a store writing to dir/events.jsonl, rotating at
// maxBytes and keeping maxFiles rotated files.
func NewStore(dir string, ring, maxBytes, maxFiles int) *Store {
	return newStore(dir, ring, maxBytes, maxFiles, 1024, true)
}

func newStore(dir string, ring, maxBytes, maxFiles, queue int, start bool) *Store {
	s := &Store{
		ring:     make([]Event, ring),
		dir:      dir,
		maxBytes: int64(maxBytes),
		maxFiles: maxFiles,
		queue:    make(chan Event, queue),
		done:     make(chan struct{}),
	}
	if start {
		go s.writer()
	} else {
		close(s.done)
	}
	return s
}

func (s *Store) Add(ev Event) {
	if ev.Version == 0 {
		ev.Version = 1
	}
	s.mu.Lock()
	s.ring[s.next] = ev
	s.next = (s.next + 1) % len(s.ring)
	if s.next == 0 {
		s.full = true
	}
	s.mu.Unlock()
	if s.closed.Load() {
		s.dropped.Add(1)
		return
	}
	select {
	case s.queue <- ev:
	default:
		s.dropped.Add(1)
	}
}

// List returns matching events, newest first.
func (s *Store) List(f Filter) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.next
	if s.full {
		n = len(s.ring)
	}
	out := []Event{}
	for i := 0; i < n; i++ {
		idx := (s.next - 1 - i + len(s.ring)) % len(s.ring)
		ev := &s.ring[idx]
		if f.match(ev) {
			out = append(out, *ev)
			if f.Limit > 0 && len(out) >= f.Limit {
				break
			}
		}
	}
	return out
}

func (s *Store) Get(id string) (Event, bool) {
	if id == "" {
		return Event{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.ring {
		if s.ring[i].ID == id {
			return s.ring[i], true
		}
	}
	return Event{}, false
}

// Export writes the matching ring events as JSONL, newest first.
func (s *Store) Export(w io.Writer, f Filter) error {
	enc := json.NewEncoder(w)
	for _, ev := range s.List(f) {
		if err := enc.Encode(ev); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Stats() Stats {
	return Stats{Written: s.written.Load(), Dropped: s.dropped.Load(), WriteErrors: s.writeErrors.Load(), Buffered: len(s.queue)}
}

// Close flushes queued events and stops the writer.
func (s *Store) Close() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed.Swap(true) {
		return
	}
	close(s.queue)
	<-s.done
}

func (s *Store) writer() {
	defer close(s.done)
	var f *os.File
	var size int64
	open := func() error {
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			return err
		}
		fh, err := os.OpenFile(filepath.Join(s.dir, fileName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		st, err := fh.Stat()
		if err != nil {
			fh.Close()
			return err
		}
		f, size = fh, st.Size()
		return nil
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	for ev := range s.queue {
		line, err := json.Marshal(ev)
		if err != nil {
			s.writeErrors.Add(1)
			continue
		}
		line = append(line, '\n')
		if int64(len(line)) > s.maxBytes {
			s.dropped.Add(1)
			continue
		}
		if f == nil {
			if err := open(); err != nil {
				s.writeErrors.Add(1)
				s.dropped.Add(1)
				continue
			}
		}
		if size+int64(len(line)) > s.maxBytes {
			f.Close()
			f = nil
			s.rotate()
			if err := open(); err != nil {
				s.writeErrors.Add(1)
				s.dropped.Add(1)
				continue
			}
		}
		n, err := f.Write(line)
		size += int64(n)
		if err != nil {
			s.writeErrors.Add(1)
			s.dropped.Add(1)
			continue
		}
		s.written.Add(1)
	}
}

func (s *Store) rotate() {
	base := filepath.Join(s.dir, fileName)
	os.Remove(fmt.Sprintf("%s.%d", base, s.maxFiles))
	for i := s.maxFiles - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", base, i), fmt.Sprintf("%s.%d", base, i+1))
	}
	os.Rename(base, base+".1")
	// Remove anything beyond the configured retention (e.g. after lowering it).
	for i := s.maxFiles + 1; i <= 20; i++ {
		os.Remove(fmt.Sprintf("%s.%d", base, i))
	}
}

// Suggestion is the narrowest exception that would have prevented one
// detection rule from matching this request.
type Suggestion struct {
	RuleID   int    `json:"rule_id"`
	Host     string `json:"host"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Argument string `json:"argument,omitempty"`
}

// nonDetection reports rule IDs that only evaluate scores/correlation and
// must never be suggested as exceptions.
func nonDetection(id int) bool {
	return (id >= 900000 && id < 912000) || (id >= 949000 && id < 950000) || (id >= 959000 && id < 960000) || (id >= 980000 && id < 981000)
}

var argVars = map[string]bool{"ARGS": true, "ARGS_GET": true, "ARGS_POST": true, "ARGS_NAMES": true, "ARGS_GET_NAMES": true, "ARGS_POST_NAMES": true}

func Suggest(ev Event) []Suggestion {
	host := ev.RouteID
	if host == "" {
		host = ev.Host
	}
	out := []Suggestion{}
	seen := map[string]bool{}
	for _, m := range ev.Matches {
		if nonDetection(m.RuleID) {
			continue
		}
		arg := ""
		onlyArgs := len(m.Targets) > 0
		for _, t := range m.Targets {
			v, k, _ := strings.Cut(t, ":")
			if !argVars[v] || k == "" {
				onlyArgs = false
				break
			}
			if arg == "" {
				arg = k
			} else if arg != k {
				onlyArgs = false
				break
			}
		}
		if !onlyArgs {
			arg = ""
		}
		key := fmt.Sprintf("%d|%s", m.RuleID, arg)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Suggestion{RuleID: m.RuleID, Host: host, Method: ev.Method, Path: ev.Path, Argument: arg})
	}
	return out
}
