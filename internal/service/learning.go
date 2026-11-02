package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/learning"
	"zoraxy-waf-plugin/internal/zoraxy"
)

// ErrActivationRequired rejects a plain save that would switch on a fresh
// installation: that has to go through Activate (learning or block now).
var ErrActivationRequired = errors.New("activate the WAF first: start the learning period or choose block now at your own risk")

// ErrAlreadyActive rejects a second activation.
var ErrAlreadyActive = errors.New("the WAF is already activated; change the mode in Settings")

// SuggestMethodAfter is how many reports of one method on a host it takes
// before the host list suggests allowing that method.
const SuggestMethodAfter = 3

// RouteSource lists Zoraxy's HTTP routes and the tags that route traffic
// through this plugin. *zoraxy.Client implements it.
type RouteSource interface {
	Routes(ctx context.Context) ([]zoraxy.Route, []string, error)
}

type routeCache struct {
	mu   sync.Mutex
	src  RouteSource
	list []zoraxy.Route
	tags []string
	at   time.Time
	err  string
}

// SetRouteSource connects the Zoraxy route list (nil: not available).
func (s *Service) SetRouteSource(src RouteSource) {
	s.routes.mu.Lock()
	s.routes.src = src
	s.routes.mu.Unlock()
}

// RefreshRoutes reads the route list from Zoraxy now.
func (s *Service) RefreshRoutes(ctx context.Context) {
	s.routes.mu.Lock()
	src := s.routes.src
	s.routes.mu.Unlock()
	if src == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	list, tags, err := src.Routes(ctx)
	s.routes.mu.Lock()
	defer s.routes.mu.Unlock()
	s.routes.at = s.opts.Now()
	if err != nil {
		s.routes.err = err.Error()
		return // keep the last good list
	}
	s.routes.list, s.routes.tags, s.routes.err = list, tags, ""
}

// RouteInfo is the cached Zoraxy route list as shown in the UI.
type RouteInfo struct {
	Available bool      `json:"available"` // a route source is connected
	Loaded    bool      `json:"loaded"`    // at least one list was read
	At        time.Time `json:"at,omitzero"`
	Error     string    `json:"error,omitempty"`
	Tags      []string  `json:"tags"` // tags that send traffic through the WAF
}

func (s *Service) routeSnapshot(maxAge time.Duration) ([]zoraxy.Route, RouteInfo) {
	s.routes.mu.Lock()
	stale := s.routes.src != nil && (s.routes.at.IsZero() || s.opts.Now().Sub(s.routes.at) > maxAge)
	s.routes.mu.Unlock()
	if stale && maxAge > 0 {
		s.RefreshRoutes(context.Background())
	}
	s.routes.mu.Lock()
	defer s.routes.mu.Unlock()
	info := RouteInfo{Available: s.routes.src != nil, Loaded: s.routes.list != nil, At: s.routes.at, Error: s.routes.err, Tags: append([]string{}, s.routes.tags...)}
	return append([]zoraxy.Route(nil), s.routes.list...), info
}

// maintenanceLoop refreshes routes, ends learning periods and saves the
// learning record once a minute until Close.
func (s *Service) maintenanceLoop() {
	every := s.opts.MaintenanceEvery
	if every == 0 {
		every = time.Minute
	}
	first := time.NewTimer(2 * time.Second)
	defer first.Stop()
	t := time.NewTicker(every)
	defer t.Stop()
	run := func() {
		s.RefreshRoutes(context.Background())
		s.LearningTick()
		s.learn.Flush()
	}
	for {
		select {
		case <-s.histDone:
			return
		case <-first.C:
			run()
		case <-t.C:
			run()
		}
	}
}

// Learning exposes the learning record (tests, UI).
func (s *Service) Learning() *learning.Store { return s.learn }

// resetLearning clears the learning records a save asks for and persists
// the result before the configuration is saved (see apply). It returns an
// undo for a configuration save that fails afterwards; on its own write
// error it undoes the reset itself. A failed save never costs evidence.
func (s *Service) resetLearning(before, after config.Config, r learnReset) (undo func(), err error) {
	// Hosts entering learning restart their period but keep their findings
	// (recorded in report mode, say); an explicit restart clears both.
	var entering []string
	for _, h := range s.learn.Hosts() {
		if before.Effective(h, "").Mode != config.ModeLearn && after.Effective(h, "").Mode == config.ModeLearn {
			entering = append(entering, h)
		}
	}
	hosts := append(append([]string{}, r.hosts...), entering...)
	if !r.all && len(hosts) == 0 {
		return func() {}, nil
	}
	prev := s.learn.Take(r.all, hosts)
	if r.all {
		s.learn.ResetAll()
	}
	for _, h := range entering {
		s.learn.RestartPeriod(h)
	}
	for _, h := range r.hosts {
		s.learn.Reset(h)
	}
	undo = func() {
		s.learn.Restore(prev, r.all)
		s.learn.Flush()
	}
	if err := s.learn.Flush(); err != nil {
		undo()
		return nil, fmt.Errorf("learning record not saved: %w", err)
	}
	return undo, nil
}

// Activate switches a fresh installation on: mode learn with a learning
// period of days, or mode block right away when the operator accepts the
// risk of false positives.
func (s *Service) Activate(mode string, days int, acceptRisk bool) (config.Config, error) {
	var note string
	switch mode {
	case config.ModeLearn:
		if days < 1 || days > config.MaxLearningDays {
			return config.Config{}, fmt.Errorf("learning period must be 1-%d days", config.MaxLearningDays)
		}
		note = fmt.Sprintf("Activated: learning, %d days per host.", days)
	case config.ModeBlock:
		if !acceptRisk {
			return config.Config{}, errors.New("blocking right away needs the explicit risk confirmation")
		}
		note = "Activated in block mode right away, without learning (risk accepted by the operator)."
	default:
		return config.Config{}, errors.New("activation mode must be learn or block")
	}
	return s.apply(note, learnReset{all: true}, func(c *config.Config) error {
		if !c.SetupRequired() {
			return ErrAlreadyActive
		}
		c.Mode = mode
		if mode == config.ModeLearn {
			c.Learning.Days = days
		}
		c.Learning.ActivatedAt = s.opts.Now().UTC()
		return nil
	})
}

// RestartLearning puts one host back into learning with a fresh period.
func (s *Service) RestartLearning(host string) (config.Config, error) {
	host = config.CanonicalHost(host)
	if !config.ValidKey(host) || host == "/" {
		return config.Config{}, errors.New("invalid host")
	}
	// The record is cleared only if the save succeeds, and before it is
	// committed (apply), so a learning check never sees the new mode with
	// the old, expired period.
	return s.apply("Learning restarted for "+host+".", learnReset{hosts: []string{host}}, func(c *config.Config) error {
		// Restart is no way around the activation dialog.
		if c.SetupRequired() {
			return ErrActivationRequired
		}
		h := c.Hosts[host]
		h.Mode = config.ModeLearn
		c.Hosts[host] = h
		return nil
	})
}

// DismissFinding marks a finding as an attack (or reopens it).
func (s *Service) DismissFinding(host, key string, dismissed bool) error {
	return s.learn.Dismiss(config.CanonicalHost(host), key, dismissed)
}

// FindingView is a finding with its current status.
type FindingView struct {
	Key string `json:"key"`
	learning.Finding
	ClientCount int `json:"client_count"`
	// ResolvedRules are the rules of this finding already covered by an
	// allowed method or an exception.
	ResolvedRules []int `json:"resolved_rules"`
	// ExceptionPath is the path an exception needs to cover the finding.
	ExceptionPath string `json:"exception_path"`
	// Status: open (likely real users; keeps the host learning), scanner
	// (no login seen; does not hold the host back), dismissed (marked as an
	// attack), resolved (method allowed or exception covers it).
	Status string `json:"status"`
}

// MethodSuggestion proposes allowing a method that was reported repeatedly.
type MethodSuggestion struct {
	Method    string `json:"method"`
	Count     int    `json:"count"`
	WithLogin int    `json:"with_login"`
}

// LearnState is where a learning host stands.
type LearnState struct {
	// State: waiting (no request yet), learning (period running), held
	// (period over, open findings left), ready (blocks at the next check).
	State    string    `json:"state"`
	Since    time.Time `json:"since,omitzero"`
	Until    time.Time `json:"until,omitzero"`
	Day      int       `json:"day"`
	Days     int       `json:"days"`
	Requests uint64    `json:"requests"`
	Open     int       `json:"open"`
}

// HostStatus is one row of the host list.
type HostStatus struct {
	Host      string               `json:"host"`
	Route     string               `json:"route,omitempty"` // Zoraxy rule when Host is an alias
	InZoraxy  bool                 `json:"in_zoraxy"`
	Protected bool                 `json:"protected"` // a tag sends it through the WAF
	Disabled  bool                 `json:"disabled"`
	Wildcard  bool                 `json:"wildcard"`
	Tags      []string             `json:"tags,omitempty"`
	SeenOnly  bool                 `json:"seen_only"` // known from traffic, not from Zoraxy
	Mode      string               `json:"mode"`      // effective
	Inherited bool                 `json:"inherited"`
	Override  *config.HostOverride `json:"override,omitempty"`
	Methods   []string             `json:"methods"`
	Learning  *LearnState          `json:"learning,omitempty"`
	Requests  uint64               `json:"requests"`
	Findings  []FindingView        `json:"findings"`
	Open      int                  `json:"open"`
	Suggest   []MethodSuggestion   `json:"suggest_methods"`
	Dropped   int                  `json:"dropped_findings,omitempty"`
	// DroppedLogin: findings with a login that could not be kept; they hold
	// the host like open findings until learning is restarted.
	DroppedLogin      int                 `json:"dropped_login,omitempty"`
	UpstreamPorts     []int               `json:"upstream_ports,omitempty"`
	SuggestedProfiles []ProfileSuggestion `json:"suggested_profiles"`
	AppliedProfiles   []ProfileState      `json:"applied_profiles"`
	DismissedProfiles []string            `json:"dismissed_profiles"`
}

// LearningSummary counts the hosts the WAF inspects by learning state.
type LearningSummary struct {
	Hosts    int       `json:"hosts"`
	Learning int       `json:"learning"` // waiting + learning + held + ready
	Held     int       `json:"held"`
	Blocking int       `json:"blocking"`
	Report   int       `json:"report"` // report only, never blocks
	Off      int       `json:"off"`    // tagged, but inspection switched off
	Open     int       `json:"open"`
	NextHost string    `json:"next_host,omitempty"`
	NextAt   time.Time `json:"next_at,omitzero"`
	NextOpen int       `json:"next_open,omitempty"` // open findings of NextHost
}

// ruleResolved: the method rule is resolved by allowing the method on the
// host, any other rule by an active exception that covers this request.
func ruleResolved(c config.Config, eff config.Effective, host string, f *learning.Finding, r learning.Rule, now time.Time) bool {
	if r.ID == config.MethodRuleID && eff.AllowsMethod(f.Method) {
		return true
	}
	for _, ex := range c.Exceptions {
		if exceptionCovers(ex, host, f, r, now) {
			return true
		}
	}
	return false
}

// exceptionCovers reports whether an exception covers every request of a
// finding. A finding that groups several paths (pattern with *) is covered
// only by a prefix exception that includes the whole pattern; an exact
// exception for one example path would leave the other paths blocked.
func exceptionCovers(ex config.Exception, host string, f *learning.Finding, r learning.Rule, now time.Time) bool {
	if ex.RuleID != r.ID || (ex.Argument != "" && ex.Argument != r.Argument) {
		return false
	}
	path := f.Path
	if i := strings.Index(path, "*"); i >= 0 {
		if !strings.HasSuffix(ex.Path, "*") {
			return false
		}
		path = path[:i]
	}
	return ex.Matches(host, "", f.Method, path, now)
}

// ExceptionPath is the narrowest exception path that covers a finding: the
// exact path, or the prefix up to the first ID segment plus *.
func ExceptionPath(pattern string) string {
	if i := strings.Index(pattern, "*"); i >= 0 {
		return pattern[:i] + "*"
	}
	return pattern
}

func findingStatus(c config.Config, eff config.Effective, host string, f *learning.Finding, now time.Time) string {
	resolved := len(f.Rules) > 0
	for _, r := range f.Rules {
		if !ruleResolved(c, eff, host, f, r, now) {
			resolved = false
		}
	}
	switch {
	case resolved:
		return "resolved"
	case f.Dismissed:
		return "dismissed"
	case f.WithLogin > 0:
		return "open"
	}
	return "scanner"
}

// HostStatuses lists every host the WAF knows: Zoraxy routes (and their
// aliases), configured overrides and hosts seen in traffic. maxAge > 0
// refreshes a route list older than that first.
func (s *Service) HostStatuses(maxAge time.Duration) ([]HostStatus, RouteInfo) {
	c := s.Current()
	routes, info := s.routeSnapshot(maxAge)
	return hostStatuses(c, routes, info, s.learn.Snapshot(), s.opts.Now()), info
}

func hostStatuses(c config.Config, routes []zoraxy.Route, info RouteInfo, rec map[string]learning.Host, now time.Time) []HostStatus {
	rows := map[string]*HostStatus{}
	add := func(host string) *HostStatus {
		if r := rows[host]; r != nil {
			return r
		}
		r := &HostStatus{Host: host, Wildcard: strings.Contains(host, "*")}
		rows[host] = r
		return r
	}
	for _, rt := range routes {
		for i, h := range append([]string{rt.Host}, rt.Aliases...) {
			r := add(h)
			r.InZoraxy, r.Protected, r.Disabled, r.Tags = true, rt.Protected, rt.Disabled, rt.Tags
			r.UpstreamPorts = append([]int(nil), rt.UpstreamPorts...)
			if i > 0 {
				r.Route = rt.Host
			}
		}
	}
	for h := range c.Hosts {
		if h != "/" {
			add(h)
		}
	}
	for h := range rec {
		add(h)
	}
	out := make([]HostStatus, 0, len(rows))
	for _, r := range rows {
		if !r.InZoraxy {
			// A host with traffic is inspected by definition. Without a route
			// list nothing is known about tags, so a configured host counts
			// as inspected; with a list, an override for a host Zoraxy does
			// not route and that never had traffic is a leftover.
			_, seen := rec[r.Host]
			_, configured := c.Hosts[r.Host]
			r.SeenOnly = seen
			r.Protected = seen || (configured && !info.Loaded)
		}
		eff := c.Effective(r.Host, "")
		r.Mode = eff.Mode
		r.Methods = append([]string{}, eff.Methods...)
		if o, ok := c.Hosts[r.Host]; ok {
			oc := o
			r.Override = &oc
			r.Inherited = o.Mode == "" || o.Mode == config.ModeInherit
		} else {
			r.Inherited = true
		}
		hr, has := rec[r.Host]
		methodHits := map[string]*MethodSuggestion{}
		if has {
			r.Requests, r.Dropped, r.DroppedLogin = hr.Requests, hr.Dropped, hr.DroppedLogin
			r.Open = hr.DroppedLogin // lost login evidence holds like an open finding
			for _, k := range learning.SortedKeys(hr) {
				f := hr.Findings[k]
				st := findingStatus(c, eff, r.Host, f, now)
				if st == "open" {
					r.Open++
				}
				if f.HasRule(config.MethodRuleID) && !eff.AllowsMethod(f.Method) && config.ValidMethod(f.Method) {
					m := methodHits[f.Method]
					if m == nil {
						m = &MethodSuggestion{Method: f.Method}
						methodHits[f.Method] = m
					}
					m.Count += f.Count
					m.WithLogin += f.WithLogin
				}
				fv := FindingView{Key: k, Finding: *f, ClientCount: len(f.Clients), Status: st, ResolvedRules: []int{}, ExceptionPath: ExceptionPath(f.Path)}
				for _, rl := range f.Rules {
					if ruleResolved(c, eff, r.Host, f, rl, now) {
						fv.ResolvedRules = append(fv.ResolvedRules, rl.ID)
					}
				}
				r.Findings = append(r.Findings, fv)
			}
		}
		decorateProfiles(r, c, hr, now)
		if r.Findings == nil {
			r.Findings = []FindingView{}
		}
		r.Suggest = []MethodSuggestion{}
		for _, m := range methodHits {
			if m.Count >= SuggestMethodAfter {
				r.Suggest = append(r.Suggest, *m)
			}
		}
		sort.Slice(r.Suggest, func(i, j int) bool { return r.Suggest[i].Method < r.Suggest[j].Method })
		if eff.Mode == config.ModeLearn && r.Protected && !r.Disabled {
			ls := &LearnState{State: "waiting", Days: c.Learning.Days, Open: r.Open, Requests: r.Requests}
			if has && !hr.Since.IsZero() {
				ls.Since = hr.Since
				ls.Until = hr.Since.Add(time.Duration(c.Learning.Days) * 24 * time.Hour)
				ls.Day = int(now.Sub(hr.Since)/(24*time.Hour)) + 1
				if ls.Day > ls.Days {
					ls.Day = ls.Days
				}
				switch {
				case now.Before(ls.Until):
					ls.State = "learning"
				case ls.Open > 0:
					ls.State = "held"
				default:
					ls.State = "ready"
				}
			}
			r.Learning = ls
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// Summarize counts the inspected hosts by learning state.
func SummarizeLearning(rows []HostStatus) LearningSummary {
	var s LearningSummary
	for _, r := range rows {
		if !r.Protected || r.Disabled || r.Wildcard {
			continue
		}
		s.Hosts++
		s.Open += r.Open
		switch {
		case r.Learning != nil:
			s.Learning++
			if r.Learning.State == "held" {
				s.Held++
			}
			if !r.Learning.Until.IsZero() && (s.NextAt.IsZero() || r.Learning.Until.Before(s.NextAt)) && r.Learning.State == "learning" {
				s.NextAt, s.NextHost, s.NextOpen = r.Learning.Until, r.Host, r.Open
			}
		case r.Mode == config.ModeBlock:
			s.Blocking++
		case r.Mode == config.ModeReport:
			s.Report++
		case r.Mode == config.ModeOff:
			s.Off++
		}
	}
	return s
}

// LearningTick switches every host whose learning period is over and that
// has no open finding to block, one audited revision per host. It returns
// the hosts switched.
func (s *Service) LearningTick() []string {
	rows, _ := s.HostStatuses(0)
	var done []string
	for _, r := range rows {
		if r.Learning == nil || r.Learning.State != "ready" || !config.ValidKey(r.Host) || r.Host == "/" {
			continue
		}
		if s.graduate(r.Host, r.Learning) == nil {
			done = append(done, r.Host)
		}
	}
	return done
}

// graduate switches one ready host to block. It decides again under
// applyMu and refuses a host that is gone or no longer ready.
func (s *Service) graduate(host string, ls *LearnState) error {
	{
		note := fmt.Sprintf("Learning finished for %s after %d days: %d requests checked, no open finding. The host now blocks attacks.", host, ls.Days, ls.Requests)
		_, err := s.ApplyNote(note, func(c *config.Config) error {
			// Decide again under applyMu with the current configuration and
			// record: a restart, a new finding, a removed exception or a longer
			// period since the first look must stop the switch.
			now := s.opts.Now()
			routes, info := s.routeSnapshot(0)
			ready := false
			for _, cur := range hostStatuses(*c, routes, info, s.learn.Snapshot(), now) {
				if cur.Host == host {
					ready = cur.Learning != nil && cur.Learning.State == "ready"
				}
			}
			if !ready {
				return errors.New("host no longer ready")
			}
			h := c.Hosts[host]
			h.Mode = config.ModeBlock
			c.Hosts[host] = h
			return nil
		})
		return err
	}
}
