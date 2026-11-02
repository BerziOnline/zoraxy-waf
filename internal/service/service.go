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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"zoraxy-waf-plugin/internal/alerts"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/crsplugins"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/engine/coraza"
	"zoraxy-waf-plugin/internal/engine/crowdsec"
	"zoraxy-waf-plugin/internal/events"
	"zoraxy-waf-plugin/internal/history"
	"zoraxy-waf-plugin/internal/learning"
	"zoraxy-waf-plugin/internal/profiles"
	"zoraxy-waf-plugin/internal/wire"
)

type Options struct {
	DataDir string
	Now     func() time.Time
	Build   func(config.Config) (engine.Engine, error)
	// SetGCPercent replaces runtime/debug.SetGCPercent in tests.
	SetGCPercent func(int) int
	// MaintenanceEvery is the interval of route refresh, learning check and
	// learning save (0: one minute, negative: off, for tests with a clock).
	MaintenanceEvery time.Duration
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
	// BodiesMissing counts requests with a body that Zoraxy sent without it
	// (a Zoraxy without dynamic_capture_sniff_body_kb).
	BodiesMissing uint64
	// ZoraxyBodyKB is set when Zoraxy sends less of the body than a host is
	// set to inspect: it read the body size at its start, before a change.
	ZoraxyBodyKB int
}
type snapshot struct {
	cfg     config.Config
	engine  engine.Engine
	sem     chan struct{} // inspection slots, sized cfg.MaxConcurrent
	refs    int
	retired bool
}

func newSnapshot(c config.Config, e engine.Engine) *snapshot {
	return &snapshot{cfg: c, engine: e, sem: make(chan struct{}, c.MaxConcurrent)}
}

type Service struct {
	applyMu     sync.Mutex
	inflight    sync.WaitGroup
	mu          sync.Mutex
	current     *snapshot
	closed      bool
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
	// bodiesMissing and zoraxyBodyKB feed Health.BodiesMissing / ZoraxyBodyKB.
	bodiesMissing atomic.Uint64
	zoraxyBodyKB  atomic.Int64
	notifier      *alerts.Notifier
	gc            *gcControl
	learn         *learning.Store
	routes        routeCache
}

func build(c config.Config) (engine.Engine, error) {
	if c.Engine == config.EngineCrowdSec {
		return crowdsec.New(crowdsec.Config{URL: c.CrowdSec.URL, APIKey: c.CrowdSec.APIKey, Timeout: time.Duration(c.CrowdSec.TimeoutMS) * time.Millisecond})
	}
	pluginHosts := map[string][]string{}
	for host, h := range c.Hosts {
		for _, ap := range h.Profiles {
			p, ok := profiles.Get(ap.ID)
			if ok && p.CRSPlugin != "" && ap.PluginCommit == crsplugins.Commit(p.CRSPlugin) {
				pluginHosts[p.CRSPlugin] = append(pluginHosts[p.CRSPlugin], host)
			}
		}
	}
	return coraza.NewWithPlugins(c.ParanoiaLevels(), c.Coraza.AnomalyThreshold, pluginHosts)
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
	s := &Service{opts: o, gc: gc, current: newSnapshot(c, e), loadError: loadError, ev: events.NewStore(o.DataDir, c.Events.RingSize, c.Events.MaxFileKB*1024, c.Events.MaxFiles), hist: history.New(o.DataDir, o.Now), histDone: make(chan struct{}), learn: learning.Open(o.DataDir)}
	go s.hist.Run(s.histDone, time.Minute)
	if o.MaintenanceEvery >= 0 {
		go s.maintenanceLoop()
	}
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
	s.learn.Flush()
}
func (s *Service) Apply(mutate func(*config.Config) error) (config.Config, error) {
	return s.ApplyNote("", mutate)
}

// ApplyNote is Apply with a note in the change history, for changes the
// plugin makes itself (activation, learning finished).
func (s *Service) ApplyNote(note string, mutate func(*config.Config) error) (config.Config, error) {
	return s.apply(note, learnReset{}, mutate)
}

// learnReset names learning records to clear as part of a save: all of
// them (activation) or some hosts (restart). Hosts entering learning are
// reset in any case.
type learnReset struct {
	all   bool
	hosts []string
}

func (s *Service) apply(note string, reset learnReset, mutate func(*config.Config) error) (config.Config, error) {
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
	// The change is valid and its engine is built. Clear learning records
	// first and persist that, then save the configuration: a crash in
	// between leaves a fresh learning period with the old mode (it learns
	// longer), never the new mode with an old, expired period.
	undo, err := s.resetLearning(before, c, reset)
	if err != nil {
		e.Close()
		return config.Config{}, err
	}
	if err = config.Save(filepath.Join(s.opts.DataDir, "config.json"), c); err != nil {
		undo()
		e.Close()
		return config.Config{}, err
	}
	// The change history is an audit trail, never a gate: the configuration is
	// already saved, so a history write error is logged and the save succeeds.
	if herr := config.AppendHistory(s.opts.DataDir, config.HistoryEntry{Time: s.opts.Now().UTC(), Revision: c.Revision, Changes: config.Diff(before, c), Note: note, Snapshot: c.Clone()}); herr != nil {
		s.historyErrors.Add(1)
	}
	s.mu.Lock()
	old := s.current
	old.retired = true
	closeIt := old.refs == 0
	s.current = newSnapshot(c.Clone(), e)
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
		rev, activated := c.Revision, c.Learning.ActivatedAt
		*c = snap.Clone()
		c.Revision = rev
		// Activation is a fact, not a setting: a rollback never brings the
		// setup dialog back. Revisions from before learning existed get the
		// default learning period.
		c.Learning.ActivatedAt = activated
		if c.Learning.Days == 0 {
			c.Learning.Days = config.DefaultLearningDays
		}
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

// Now is the service clock (Options.Now).
func (s *Service) Now() time.Time { return s.opts.Now() }

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
	return Health{EngineName: p.cfg.Engine, Engine: p.engine.Health(), Revision: p.cfg.Revision, HistoryErrors: s.historyErrors.Load(), BodiesMissing: s.bodiesMissing.Load(), ZoraxyBodyKB: int(s.zoraxyBodyKB.Load())}
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
	mux.HandleFunc("/sniff/", s.sniff)
	mux.HandleFunc("/capture/", func(w http.ResponseWriter, r *http.Request) {
		// Required by the dynamic capture contract, but the WAF never accepts a
		// request, so nothing legitimate arrives here.
		http.Error(w, "WAF does not capture traffic", 404)
	})
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
	p, ok := s.decodePayload(w, r)
	if !ok {
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
	result, err := s.evaluate(r.Context(), snap, effective, p)
	if err == errSaturated {
		http.Error(w, "Inspection capacity exhausted", 503)
		return
	}
	if err != nil {
		http.Error(w, "WAF inspection failed", 503)
		return
	}
	JSON(w, result)
}

// sniff speaks Zoraxy's dynamic capture sniff protocol: 501 lets the request
// continue normally, 286 asks Zoraxy to answer the client with the status in
// X-Zoraxy-Deny-Status. The body prefix arrives with the same call. The WAF
// never answers 200 (accept), so it never has to proxy traffic itself.
func (s *Service) sniff(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	p, ok := s.decodePayload(w, r)
	if !ok {
		return
	}
	snap := s.acquire()
	if snap == nil {
		s.sniffFailure(w, false)
		return
	}
	defer s.release(snap)
	effective := snap.cfg.Effective(p.Host, p.RouteID)
	if effective.Mode == config.ModeOff {
		s.mu.Lock()
		s.stats.Skipped++
		s.mu.Unlock()
		w.WriteHeader(wire.SniffSkip)
		return
	}
	if s.noteBody(p, effective.MaxBodyKB) && effective.FailClosed && effective.Mode == config.ModeBlock {
		// The request announced a body that Zoraxy did not send: inspection
		// would be incomplete, and fail-closed hosts reject what they cannot inspect.
		w.Header().Set("X-Zoraxy-Deny-Status", "503")
		w.Header().Set("X-Zoraxy-Deny-Reason", "waf-body-missing")
		w.WriteHeader(wire.SniffDeny)
		return
	}
	result, err := s.evaluate(r.Context(), snap, effective, p)
	if err != nil {
		// Fail closed only applies to enforcing hosts: report and learning
		// never block a request, not even when inspection fails.
		s.sniffFailure(w, effective.FailClosed && effective.Mode == config.ModeBlock)
		return
	}
	if result.Action == "deny" {
		w.Header().Set("X-Zoraxy-Deny-Status", strconv.Itoa(result.Status))
		if result.Reason != "" {
			w.Header().Set("X-Zoraxy-Deny-Reason", result.Reason)
		}
		w.WriteHeader(wire.SniffDeny)
		return
	}
	w.WriteHeader(wire.SniffSkip)
}

// sniffFailure maps an inspection failure to the configured failure policy:
// fail-closed answers the client 503, fail-open lets the request through.
func (s *Service) sniffFailure(w http.ResponseWriter, failClosed bool) {
	if failClosed {
		w.Header().Set("X-Zoraxy-Deny-Status", "503")
		w.Header().Set("X-Zoraxy-Deny-Reason", "waf-unavailable")
		w.WriteHeader(wire.SniffDeny)
		return
	}
	w.WriteHeader(wire.SniffSkip)
}

// denyReason is the short token Zoraxy writes into its access log
// (plugin-deny:waf-942100): the most severe rule that detected the attack
// (the first one on a tie), so a log line leads straight to the event in the
// WAF. The anomaly-score rules that only add up the detections are skipped.
func denyReason(d engine.Decision) string {
	best, rank := 0, 99
	for _, m := range d.Matches {
		if m.RuleID >= 949000 && m.RuleID <= 949999 || m.RuleID >= 980000 && m.RuleID <= 980999 {
			continue
		}
		if r := severityRank(m.Severity); r < rank {
			best, rank = m.RuleID, r
		}
	}
	if best == 0 {
		return "waf"
	}
	return "waf-" + strconv.Itoa(best)
}

// severityRank orders CRS severities, most severe first.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "emergency":
		return 0
	case "alert":
		return 1
	case "critical":
		return 2
	case "error":
		return 3
	case "warning":
		return 4
	case "notice":
		return 5
	}
	return 6
}

// noteBody records whether Zoraxy delivers the body the host is set to
// inspect, so the overview can say when Zoraxy needs an update or a restart.
// It reports true when the request announced a body that did not arrive.
func (s *Service) noteBody(p wire.InspectPayload, wantKB int) (missing bool) {
	if !p.BodyIncluded {
		if declaresBody(p.Header) {
			s.bodiesMissing.Add(1)
			return true
		}
		return false
	}
	// Zoraxy sends bodies now (it was updated and restarted).
	s.bodiesMissing.Store(0)
	// Zoraxy cuts every body at one size for the whole plugin; a cut body is
	// that size. Note it when a host wants more, clear the note only when more
	// than the noted size arrives (a host with a small limit proves nothing).
	if noted := s.zoraxyBodyKB.Load(); noted > 0 && int64(len(p.Body)) > noted*1024 {
		s.zoraxyBodyKB.Store(0)
	}
	if p.BodyTruncated && len(p.Body) < wantKB*1024 {
		s.zoraxyBodyKB.Store(int64(len(p.Body)+1023) / 1024) // rounded up: never 0 for a short cut
	}
	return false
}

// declaresBody reports whether the request headers announce a body.
func declaresBody(h map[string][]string) bool {
	for k, v := range h {
		switch strings.ToLower(k) {
		case "content-length":
			if len(v) > 0 {
				if n, err := strconv.Atoi(strings.TrimSpace(v[0])); err == nil && n > 0 {
					return true
				}
			}
		case "transfer-encoding":
			if len(v) > 0 && v[0] != "" {
				return true
			}
		}
	}
	return false
}

func (s *Service) decodePayload(w http.ResponseWriter, r *http.Request) (wire.InspectPayload, bool) {
	const maxPayload = 2 << 20
	if r.ContentLength > maxPayload {
		http.Error(w, "Payload too large", 413)
		return wire.InspectPayload{}, false
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
		return wire.InspectPayload{}, false
	}
	return p, true
}

var errSaturated = errors.New("inspection capacity exhausted")

// evaluate runs the engine for one request and records stats, history and
// events. It returns the decision, or an error when the engine failed or the
// service is saturated; the caller maps that to its transport.
func (s *Service) evaluate(ctx context.Context, snap *snapshot, effective config.Effective, p wire.InspectPayload) (wire.InspectResult, error) {
	// Capacity: wait briefly for a free inspection slot instead of giving up at
	// once. A burst (parallel uploads from one app) then costs a few milliseconds
	// of latency rather than requests that pass uninspected or are rejected.
	waitCtx, cancelWait := context.WithTimeout(ctx, time.Duration(effective.BodyTimeoutMS)*time.Millisecond)
	defer cancelWait()
	sem := snap.sem
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-waitCtx.Done():
		s.mu.Lock()
		s.stats.Saturated++
		s.mu.Unlock()
		return wire.InspectResult{}, errSaturated
	}
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
		// Per-host methods: the CRS method rule is removed for this request
		// only when the host allows its method; all other rules still run.
		if len(effective.Methods) > 0 && !config.IsCRSMethod(req.Method) && effective.AllowsMethod(req.Method) {
			opts.Exclusions = append(opts.Exclusions, engine.Exclusion{RuleID: config.MethodRuleID})
		}
		for _, ex := range snap.cfg.Exceptions {
			if ex.Matches(req.Host, req.RouteID, req.Method, path, s.opts.Now()) {
				opts.Exclusions = append(opts.Exclusions, engine.Exclusion{RuleID: ex.RuleID, Argument: ex.Argument})
				ids = append(ids, ex.ID)
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(effective.BodyTimeoutMS)*time.Millisecond)
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
			result.Reason = denyReason(d)
		}
		eventStatus = d.Status
	} else if req.BodyTruncated {
		// The inspected prefix is clean, the rest was not seen. Default is to
		// let the request through with partial coverage (uploads are normal
		// traffic); reject_oversize turns this into a 413 in block mode.
		action = events.ActionOversize
		if effective.Mode == config.ModeBlock && effective.RejectOversize {
			result.Action = "deny"
			result.Status = 413
			result.Reason = "waf-body-too-large"
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
	// Report mode counts too: the host list then also shows hosts Zoraxy's
	// route list does not (no API key), and a host entering learning starts
	// a fresh period anyway.
	if effective.Mode == config.ModeLearn || effective.Mode == config.ModeReport {
		s.learn.Observe(effective.Key, s.opts.Now())
		s.learn.ObservePath(effective.Key, path, learning.WithLoginHeader(req.Header), s.opts.Now())
	}
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
		if action == events.ActionWouldBlock && (effective.Mode == config.ModeLearn || effective.Mode == config.ModeReport) {
			// Login is judged on all original header names; the event keeps a
			// capped list only.
			s.learn.Record(effective.Key, ev, learning.WithLoginHeader(req.Header))
		}
	}
	return result, err
}
