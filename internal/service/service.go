// Package service owns configuration snapshots and the core-facing inspection API.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"zoraxy-waf-plugin/internal/alerts"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/engine/coraza"
	"zoraxy-waf-plugin/internal/engine/crowdsec"
	"zoraxy-waf-plugin/internal/events"
	"zoraxy-waf-plugin/internal/history"
	"zoraxy-waf-plugin/internal/wire"
)

type Options struct {
	DataDir string
	Now     func() time.Time
	Build   func(config.Config) (engine.Engine, error)
	// SetGCPercent replaces runtime/debug.SetGCPercent in tests.
	SetGCPercent func(int) int
}
type Stats struct {
	Inspected, Allowed, WouldBlock, Blocked, Oversize, Errors, Saturated, Skipped, BadRequests uint64
	LatencyP95MS                                                                               float64
}
type Health struct {
	EngineName string
	Engine     engine.Health
	Revision   uint64
	// HistoryErrors is the number of configuration saves whose audit-trail
	// line could not be written (the save itself succeeded).
	HistoryErrors uint64
}
type snapshot struct {
	cfg     config.Config
	engine  engine.Engine
	refs    int
	retired bool
}
type Service struct {
	applyMu     sync.Mutex
	inflight    sync.WaitGroup
	mu          sync.Mutex
	current     *snapshot
	closed      bool
	active      int
	stats       Stats
	latencies   []float64
	nextLatency int
	ev          *events.Store
	hist        *history.Store
	histDone    chan struct{}
	opts        Options
	loadError   string
	// historyErrors counts failed audit-trail writes (surfaced in Health).
	historyErrors atomic.Uint64
	notifier      *alerts.Notifier
	gc            *gcControl
}

func build(c config.Config) (engine.Engine, error) {
	if c.Engine == config.EngineCrowdSec {
		return crowdsec.New(crowdsec.Config{URL: c.CrowdSec.URL, APIKey: c.CrowdSec.APIKey, Timeout: time.Duration(c.CrowdSec.TimeoutMS) * time.Millisecond})
	}
	return coraza.New(c.ParanoiaLevels(), c.Coraza.AnomalyThreshold)
}
func New(o Options) (*Service, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Build == nil {
		o.Build = build
	}
	c, err := config.Load(filepath.Join(o.DataDir, "config.json"))
	loadError := ""
	if err != nil {
		c = config.Default()
		if !errors.Is(err, os.ErrNotExist) {
			loadError = "Stored configuration is invalid; inspection is off. Review and explicitly save configuration."
		}
	}
	e, err := o.Build(c)
	if err != nil {
		return nil, err
	}
	gc := processGC
	if o.SetGCPercent != nil {
		gc = newGCControl(o.SetGCPercent)
	}
	gc.apply(c.GCTarget)
	s := &Service{opts: o, gc: gc, current: &snapshot{cfg: c, engine: e}, loadError: loadError, ev: events.NewStore(o.DataDir, c.Events.RingSize, c.Events.MaxFileKB*1024, c.Events.MaxFiles), hist: history.New(o.DataDir, o.Now), histDone: make(chan struct{})}
	go s.hist.Run(s.histDone, time.Minute)
	s.notifier = alerts.New("Zoraxy WAF", s.opts.Now)
	s.notifier.Apply(s.current.cfg.Alerts)
	go s.alertLoop()
	return s, nil
}
func (s *Service) acquire() *snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	p := s.current
	p.refs++
	s.inflight.Add(1)
	return p
}
func (s *Service) release(p *snapshot) {
	defer s.inflight.Done()
	s.mu.Lock()
	p.refs--
	closeIt := p.retired && p.refs == 0
	s.mu.Unlock()
	if closeIt {
		p.engine.Close()
	}
}
func (s *Service) Close() {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	p := s.current
	p.retired = true
	closeIt := p.refs == 0
	s.mu.Unlock()
	if closeIt {
		p.engine.Close()
	}
	s.inflight.Wait()
	s.ev.Close()
	close(s.histDone)
	s.hist.Flush()
}
func (s *Service) Apply(mutate func(*config.Config) error) (config.Config, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return config.Config{}, errors.New("service closed")
	}
	c := s.current.cfg.Clone()
	before := s.current.cfg.Clone()
	previousExceptions := append([]config.Exception{}, c.Exceptions...)
	s.mu.Unlock()
	if err := mutate(&c); err != nil {
		return config.Config{}, err
	}
	c.Revision++
	if err := c.Validate(); err != nil {
		return config.Config{}, err
	}
	e, err := s.opts.Build(c)
	if err != nil {
		return config.Config{}, err
	}
	if !e.Capabilities().RuleExclusions {
		for _, ex := range c.Exceptions {
			known := false
			for _, previous := range previousExceptions {
				a, b := ex, previous
				a.CreatedAt, b.CreatedAt = a.CreatedAt.UTC(), b.CreatedAt.UTC()
				a.ExpiresAt, b.ExpiresAt = a.ExpiresAt.UTC(), b.ExpiresAt.UTC()
				if a == b {
					known = true
					break
				}
			}
			if !known {
				e.Close()
				return config.Config{}, engine.ErrUnsupported
			}
		}
	}
	if err = config.Save(filepath.Join(s.opts.DataDir, "config.json"), c); err != nil {
		e.Close()
		return config.Config{}, err
	}
	// The change history is an audit trail, never a gate: the configuration is
	// already saved, so a history write error is logged and the save succeeds.
	if herr := config.AppendHistory(s.opts.DataDir, config.HistoryEntry{Time: s.opts.Now().UTC(), Revision: c.Revision, Changes: config.Diff(before, c), Snapshot: c.Clone()}); herr != nil {
		s.historyErrors.Add(1)
	}
	s.mu.Lock()
	old := s.current
	old.retired = true
	closeIt := old.refs == 0
	s.current = &snapshot{cfg: c.Clone(), engine: e}
	s.loadError = ""
	s.mu.Unlock()
	// Under applyMu, so concurrent saves apply GC targets in revision order.
	s.gc.apply(c.GCTarget)
	s.notifier.Apply(c.Alerts)
	if closeIt && old.engine != e {
		old.engine.Close()
	}
	return c.Clone(), nil
}
func (s *Service) Current() config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current.cfg.Clone()
}
func (s *Service) Policy() wire.Policy   { return s.Current().Policy() }
func (s *Service) Events() *events.Store { return s.ev }

// Changes lists the newest saved revisions with what changed (audit trail).
func (s *Service) Changes(limit int) ([]config.PublicHistoryEntry, error) {
	return config.History(s.opts.DataDir, limit)
}

// Revert makes the configuration of an earlier revision current again. It
// is a normal save (new revision, validated, engine rebuilt), so the audit
// trail shows the rollback as its own entry.
func (s *Service) Revert(revision uint64) (config.Config, error) {
	snap, err := config.Snapshot(s.opts.DataDir, revision)
	if err != nil {
		return config.Config{}, err
	}
	return s.Apply(func(c *config.Config) error {
		rev := c.Revision
		*c = snap.Clone()
		c.Revision = rev
		return nil
	})
}

// alertLoop evaluates alert conditions once a minute until Close.
func (s *Service) alertLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.histDone:
			return
		case <-t.C:
			s.notifier.Tick(context.Background(), s.alertProbe())
		}
	}
}

func (s *Service) alertProbe() alerts.Probe {
	h := s.Health()
	c := s.Current()
	p := alerts.Probe{EngineOK: h.Engine.OK, EngineDetail: h.Engine.Detail, Exceptions: map[string]alerts.Expiring{}}
	for _, e := range c.Exceptions {
		p.Exceptions[e.ID] = alerts.Expiring{Label: fmt.Sprintf("rule %d on %s %s", e.RuleID, e.Host, e.Path), ExpiresAt: e.ExpiresAt}
	}
	return p
}

// Alerts exposes the notifier (test alert, delivery counters).
func (s *Service) Alerts() *alerts.Notifier { return s.notifier }

// AlertTick evaluates alert conditions now (tests and the UI test button).
func (s *Service) AlertTick() { s.notifier.Tick(context.Background(), s.alertProbe()) }

// DataDir is the directory holding config.json, history.jsonl and events.
func (s *Service) DataDir() string { return s.opts.DataDir }

// History holds the 30-day hourly decision counters behind the overview.
func (s *Service) History() *history.Store { return s.hist }

// GCPercent is the Go GC target currently active in the plugin process.
func (s *Service) GCPercent() int { return s.gc.active() }

// GCStartPercent is the GC target the process started with (GOGC, -1 = off).
func (s *Service) GCStartPercent() int { return s.gc.start() }
func (s *Service) LoadError() string   { s.mu.Lock(); defer s.mu.Unlock(); return s.loadError }
func (s *Service) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	if len(s.latencies) > 0 {
		v := append([]float64{}, s.latencies...)
		sort.Float64s(v)
		st.LatencyP95MS = v[(len(v)-1)*95/100]
	}
	return st
}
func (s *Service) Health() Health {
	p := s.acquire()
	if p == nil {
		return Health{Engine: engine.Health{Detail: "service stopped"}}
	}
	defer s.release(p)
	return Health{EngineName: p.cfg.Engine, Engine: p.engine.Health(), Revision: p.cfg.Revision, HistoryErrors: s.historyErrors.Load()}
}
func (s *Service) Capabilities() engine.Capabilities {
	p := s.acquire()
	if p == nil {
		return engine.Capabilities{}
	}
	defer s.release(p)
	return p.engine.Capabilities()
}
func LoopbackHost(host string) bool {
	h := host
	if x, _, err := net.SplitHostPort(h); err == nil {
		h = x
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}
func JSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func (s *Service) IPCHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/policy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET required", 405)
			return
		}
		JSON(w, s.Policy())
	})
	mux.HandleFunc("/inspect", s.inspect)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !LoopbackHost(r.Host) {
			http.Error(w, "Loopback Host required", 403)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func (s *Service) inspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	const maxPayload = 2 << 20
	if r.ContentLength > maxPayload {
		http.Error(w, "Payload too large", 413)
		return
	}
	p, err := wire.DecodeInspectPayload(r.Body, maxPayload)
	if err != nil {
		s.mu.Lock()
		s.stats.BadRequests++
		s.mu.Unlock()
		code := 400
		if strings.Contains(err.Error(), "size limit") {
			code = 413
		}
		http.Error(w, "Invalid inspection payload", code)
		return
	}
	snap := s.acquire()
	if snap == nil {
		http.Error(w, "Service stopped", 503)
		return
	}
	defer s.release(snap)
	effective := snap.cfg.Effective(p.Host, p.RouteID)
	if effective.Mode == config.ModeOff {
		s.mu.Lock()
		s.stats.Skipped++
		s.mu.Unlock()
		JSON(w, wire.InspectResult{Action: "allow"})
		return
	}
	s.mu.Lock()
	if s.active >= snap.cfg.MaxConcurrent {
		s.stats.Saturated++
		s.mu.Unlock()
		http.Error(w, "Inspection capacity exhausted", 503)
		return
	}
	s.active++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active--; s.mu.Unlock() }()
	start := time.Now()
	req := &engine.Request{ID: events.NewID(), Method: p.Method, RawURI: p.RequestURI, Proto: p.Proto, Host: p.Host, RouteID: p.RouteID, ClientIP: p.ClientIP, Header: p.Header, Body: p.Body, BodyTruncated: p.BodyTruncated}
	if len(req.Body) > effective.MaxBodyKB*1024 {
		req.Body = req.Body[:effective.MaxBodyKB*1024]
		req.BodyTruncated = true
	}
	path, _, _ := strings.Cut(req.RawURI, "?")
	opts := engine.Options{ParanoiaLevel: effective.ParanoiaLevel}
	ids := []string{}
	if snap.engine.Capabilities().RuleExclusions {
		for _, ex := range snap.cfg.Exceptions {
			if ex.Matches(req.Host, req.RouteID, req.Method, path, s.opts.Now()) {
				opts.Exclusions = append(opts.Exclusions, engine.Exclusion{RuleID: ex.RuleID, Argument: ex.Argument})
				ids = append(ids, ex.ID)
			}
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(effective.BodyTimeoutMS)*time.Millisecond)
	defer cancel()
	d, err := snap.engine.Inspect(ctx, req, opts)
	if err == nil {
		err = ctx.Err()
	}
	duration := float64(time.Since(start)) / float64(time.Millisecond)
	eventStatus := 0
	result := wire.InspectResult{Action: "allow"}
	action := events.ActionAllowed
	if err != nil {
		action = events.ActionError
		eventStatus = 503
	} else if d.Interrupted {
		action = events.ActionWouldBlock
		if effective.Mode == config.ModeBlock {
			action = events.ActionBlocked
			result.Action = "deny"
			result.Status = d.Status
			if result.Status < 400 || result.Status > 599 {
				result.Status = 403
			}
			result.Reason = "Blocked by WAF"
		}
		eventStatus = d.Status
	} else if req.BodyTruncated {
		action = events.ActionOversize
		if effective.Mode == config.ModeBlock {
			result.Action = "deny"
			result.Status = 413
			result.Reason = "Request body exceeds WAF inspection limit"
		}
		eventStatus = result.Status
	}
	s.mu.Lock()
	s.stats.Inspected++
	switch action {
	case events.ActionAllowed:
		s.stats.Allowed++
	case events.ActionWouldBlock:
		s.stats.WouldBlock++
	case events.ActionBlocked:
		s.stats.Blocked++
	case events.ActionError:
		s.stats.Errors++
	case events.ActionOversize:
		s.stats.Oversize++
	}
	if len(s.latencies) < 1024 {
		s.latencies = append(s.latencies, duration)
	} else {
		s.latencies[s.nextLatency] = duration
		s.nextLatency = (s.nextLatency + 1) % 1024
	}
	s.mu.Unlock()
	s.hist.Record(action)
	if action == events.ActionBlocked || action == events.ActionWouldBlock {
		s.notifier.RecordAttack()
	}
	if action != events.ActionAllowed {
		// Allowed requests are counted, but never persisted. Avoid constructing
		// and scrubbing an event (and querying audit health) only to discard it.
		ev := events.FromRequest(req, d.Matches)
		ev.Time = s.opts.Now().UTC()
		ev.Engine = snap.cfg.Engine
		ev.RuleSet = snap.engine.Health().RuleSet
		ev.Revision = snap.cfg.Revision
		ev.Mode = effective.Mode
		ev.Paranoia = effective.ParanoiaLevel
		ev.DurationMS = duration
		ev.BodyBytes = len(req.Body)
		ev.Coverage = "full"
		if req.BodyTruncated {
			ev.Coverage = "partial"
		}
		ev.AnomalyScore = d.AnomalyScore
		ev.RuleDetails = d.RuleDetails
		ev.Exceptions = ids
		ev.Status = eventStatus
		ev.Action = action
		if err != nil {
			ev.Error = "Engine inspection failed"
		}
		s.ev.Add(ev)
		result.EventID = ev.ID
	}
	if err != nil {
		http.Error(w, "WAF inspection failed", 503)
		return
	}
	JSON(w, result)
}
