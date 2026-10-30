// Package config holds the plugin's persisted configuration, its validation
// and the derived per-host effective policy.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
	"zoraxy-waf-plugin/internal/alerts"

	"zoraxy-waf-plugin/internal/wire"
)

const (
	EngineCoraza   = "coraza"
	EngineCrowdSec = "crowdsec"

	ModeInherit = "inherit"
	ModeOff     = "off"
	ModeReport  = "report"
	ModeBlock   = "block"
)

type CorazaSettings struct {
	ParanoiaLevel    int `json:"paranoia_level"`
	AnomalyThreshold int `json:"anomaly_threshold"`
}

type CrowdSecSettings struct {
	URL       string `json:"url"`
	APIKey    string `json:"api_key"`
	TimeoutMS int    `json:"timeout_ms"`
}

type EventSettings struct {
	RingSize  int `json:"ring_size"`
	MaxFileKB int `json:"max_file_kb"`
	MaxFiles  int `json:"max_files"`
}

type HostOverride struct {
	Mode          string `json:"mode"`
	MaxBodyKB     int    `json:"max_body_kb,omitempty"`
	BodyTimeoutMS int    `json:"body_timeout_ms,omitempty"`
	ParanoiaLevel int    `json:"paranoia_level,omitempty"`
}

type Exception struct {
	ID        string    `json:"id"`
	RuleID    int       `json:"rule_id"`
	Host      string    `json:"host"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path,omitempty"`
	Argument  string    `json:"argument,omitempty"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Config struct {
	SchemaVersion      int                     `json:"schema_version"`
	Revision           uint64                  `json:"revision"`
	Engine             string                  `json:"engine"`
	Mode               string                  `json:"mode"`
	FailClosed         bool                    `json:"fail_closed"`
	InvertFailureHosts []string                `json:"invert_failure_hosts"`
	MaxBodyKB          int                     `json:"max_body_kb"`
	BodyTimeoutMS      int                     `json:"body_timeout_ms"`
	MaxConcurrent      int                     `json:"max_concurrent"`
	Coraza             CorazaSettings          `json:"coraza"`
	CrowdSec           CrowdSecSettings        `json:"crowdsec"`
	Hosts              map[string]HostOverride `json:"hosts"`
	Exceptions         []Exception             `json:"exceptions"`
	Events             EventSettings           `json:"events"`
	Alerts             alerts.Settings         `json:"alerts"`
	// GCTarget is the Go GC target of the plugin process ("Speed" setting):
	// how far plugin memory may grow before freed request data is cleaned up.
	// Higher = fewer clean-ups = more requests/s for more RAM. Same rules and
	// decisions. One of GCTargets; measured in docs/PERFORMANCE.md §4.
	GCTarget int `json:"gc_target"`
}

type Effective struct {
	Key           string
	Mode          string
	FailClosed    bool
	MaxBodyKB     int
	BodyTimeoutMS int
	ParanoiaLevel int
}

const (
	SchemaVersion       = 1
	MaxExceptionLife    = 366 * 24 * time.Hour
	maxHosts            = 1000
	maxExceptions       = 1000
	maxInversionEntries = 1000
)

// Default is the fresh-install configuration: inspection off globally,
// Coraza CRS PL1 ready for explicit host enrolment.
func Default() Config {
	return Config{
		SchemaVersion:      SchemaVersion,
		Engine:             EngineCoraza,
		Mode:               ModeOff,
		InvertFailureHosts: []string{},
		MaxBodyKB:          64,
		BodyTimeoutMS:      5000,
		MaxConcurrent:      16,
		Coraza:             CorazaSettings{ParanoiaLevel: 1, AnomalyThreshold: 5},
		CrowdSec:           CrowdSecSettings{TimeoutMS: 500},
		Hosts:              map[string]HostOverride{},
		Exceptions:         []Exception{},
		Events:             EventSettings{RingSize: 1000, MaxFileKB: 10240, MaxFiles: 3},
		Alerts:             alerts.Defaults(),
		GCTarget:           DefaultGCTarget,
	}
}

// GCTargets are the selectable "Speed" levels; DefaultGCTarget is the default.
var GCTargets = []int{100, 200, 400, 800}

const DefaultGCTarget = 400

func validGCTarget(v int) bool {
	for _, t := range GCTargets {
		if v == t {
			return true
		}
	}
	return false
}

func validMode(m string) bool { return m == ModeOff || m == ModeReport || m == ModeBlock }

// ValidKey reports whether k is an acceptable host / route identity:
// lowercase, no whitespace or path, at most 253 bytes. The explicit `/`
// sentinel identifies the default site, not a path prefix. Wildcard route IDs
// such as "*.example.com" are literal identities, never patterns.
func ValidKey(k string) bool {
	if k == "/" {
		return true
	}
	if k == "" || len(k) > 253 {
		return false
	}
	for _, c := range k {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case strings.ContainsRune(".-_*:[]", c):
		default:
			return false
		}
	}
	return true
}

func (c Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if c.SchemaVersion != SchemaVersion {
		add("schema_version must be %d", SchemaVersion)
	}
	if c.Engine != EngineCoraza && c.Engine != EngineCrowdSec {
		add("engine must be coraza or crowdsec")
	}
	if !validMode(c.Mode) {
		add("mode must be off, report or block")
	}
	if c.MaxBodyKB < 1 || c.MaxBodyKB > 1024 {
		add("max_body_kb must be 1-1024")
	}
	if c.BodyTimeoutMS < 100 || c.BodyTimeoutMS > 30000 {
		add("body_timeout_ms must be 100-30000")
	}
	if c.MaxConcurrent < 1 || c.MaxConcurrent > 1024 {
		add("max_concurrent must be 1-1024")
	}
	if !validGCTarget(c.GCTarget) {
		add("gc_target must be 100, 200, 400 or 800")
	}
	if c.Coraza.ParanoiaLevel < 1 || c.Coraza.ParanoiaLevel > 4 {
		add("coraza.paranoia_level must be 1-4")
	}
	if c.Coraza.AnomalyThreshold < 1 || c.Coraza.AnomalyThreshold > 1000 {
		add("coraza.anomaly_threshold must be 1-1000")
	}
	if err := c.Alerts.Validate(); err != nil {
		return err
	}
	if c.Events.RingSize < 100 || c.Events.RingSize > 10000 {
		add("events.ring_size must be 100-10000")
	}
	if c.Events.MaxFileKB < 64 || c.Events.MaxFileKB > 102400 {
		add("events.max_file_kb must be 64-102400")
	}
	if c.Events.MaxFiles < 1 || c.Events.MaxFiles > 20 {
		add("events.max_files must be 1-20")
	}
	if len(c.Hosts) > maxHosts {
		add("too many host overrides")
	}
	for k, h := range c.Hosts {
		if !ValidKey(k) {
			add("host key %q must be a lowercase host or route id", k)
		}
		if h.Mode != ModeInherit && !validMode(h.Mode) {
			add("host %q: mode must be inherit, off, report or block", k)
		}
		if h.MaxBodyKB != 0 && (h.MaxBodyKB < 1 || h.MaxBodyKB > 1024) {
			add("host %q: max_body_kb must be 1-1024", k)
		}
		if h.BodyTimeoutMS != 0 && (h.BodyTimeoutMS < 100 || h.BodyTimeoutMS > 30000) {
			add("host %q: body_timeout_ms must be 100-30000", k)
		}
		if h.ParanoiaLevel < 0 || h.ParanoiaLevel > 4 {
			add("host %q: paranoia_level must be 1-4 or 0 to inherit", k)
		}
	}
	if len(c.InvertFailureHosts) > maxInversionEntries {
		add("too many invert_failure_hosts entries")
	}
	for _, k := range c.InvertFailureHosts {
		if !ValidKey(k) {
			add("invert_failure_hosts entry %q must be an exact lowercase host or route id", k)
		}
	}
	if len(c.Exceptions) > maxExceptions {
		add("too many exceptions")
	}
	ids := map[string]bool{}
	for _, e := range c.Exceptions {
		if err := e.validate(); err != nil {
			add("exception %q: %v", e.ID, err)
		}
		if ids[e.ID] {
			add("duplicate exception id %q", e.ID)
		}
		ids[e.ID] = true
	}
	if c.Engine == EngineCrowdSec || c.CrowdSec.URL != "" {
		if err := ValidateCrowdSecURL(c.CrowdSec.URL); err != nil {
			add("crowdsec.url: %v", err)
		}
		if c.CrowdSec.APIKey == "" || len(c.CrowdSec.APIKey) > 512 || strings.ContainsAny(c.CrowdSec.APIKey, "\r\n") {
			add("crowdsec.api_key is required (max 512 bytes, single line)")
		}
	}
	if c.CrowdSec.TimeoutMS < 20 || c.CrowdSec.TimeoutMS > 5000 {
		add("crowdsec.timeout_ms must be 20-5000")
	}
	return errors.Join(errs...)
}

// ValidateCrowdSecURL allows plain HTTP only to literal loopback addresses
// and requires TLS for anything else. Credentials in the URL are rejected.
func ValidateCrowdSecURL(raw string) error {
	if raw == "" {
		return errors.New("required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("not a valid URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("must not contain credentials, query or fragment")
	}
	if u.Hostname() == "" {
		return errors.New("host required")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return errors.New("plain http is only allowed to a literal loopback address; use https for remote AppSec")
		}
		return nil
	default:
		return errors.New("scheme must be http (loopback) or https")
	}
}

func (e Exception) validate() error {
	switch {
	case e.ID == "" || len(e.ID) > 64:
		return errors.New("id required")
	case e.RuleID < 1 || e.RuleID > 99999999:
		return errors.New("rule_id must be a positive CRS/Coraza rule id")
	case !ValidKey(e.Host):
		return errors.New("host must be an exact lowercase host or route id (global exceptions are not allowed)")
	case e.Method != "" && (e.Method != strings.ToUpper(e.Method) || strings.ContainsAny(e.Method, " \t/") || len(e.Method) > 16):
		return errors.New("method must be empty (any) or an uppercase HTTP method")
	case e.Path == "" || !strings.HasPrefix(e.Path, "/") || len(e.Path) > 1024 || strings.ContainsAny(e.Path, " ?#\r\n"):
		return errors.New("path scope is required and must start with / (append * for prefix)")
	case len(e.Argument) > 256 || strings.ContainsAny(e.Argument, "\r\n"):
		return errors.New("argument name too long or multi-line")
	case len(strings.TrimSpace(e.Reason)) < 3 || len(e.Reason) > 500:
		return errors.New("reason required (3-500 characters)")
	case e.CreatedAt.IsZero() || e.ExpiresAt.IsZero():
		return errors.New("created_at and expires_at required")
	case !e.ExpiresAt.After(e.CreatedAt):
		return errors.New("expires_at must be after created_at")
	case e.ExpiresAt.Sub(e.CreatedAt) > MaxExceptionLife:
		return errors.New("expiry must be within 366 days")
	}
	return nil
}

// Clone returns a deep copy.
func (c Config) Clone() Config {
	d := c
	d.Alerts = c.Alerts.Clone()
	d.InvertFailureHosts = append([]string{}, c.InvertFailureHosts...)
	d.Hosts = make(map[string]HostOverride, len(c.Hosts))
	for k, v := range c.Hosts {
		d.Hosts[k] = v
	}
	d.Exceptions = append([]Exception{}, c.Exceptions...)
	return d
}

// CanonicalHost lowercases, strips a port and a trailing dot.
func CanonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	} else if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return strings.TrimSuffix(h, ".")
}

// lookupKey returns the hosts-map key applying to a request: the route id
// when configured, otherwise the canonical host.
func (c Config) lookupKey(host, routeID string) (string, bool) {
	if r := strings.ToLower(routeID); r != "" {
		if _, ok := c.Hosts[r]; ok {
			return r, true
		}
	}
	h := CanonicalHost(host)
	_, ok := c.Hosts[h]
	return h, ok
}

func (c Config) inverted(host, routeID string) bool {
	r, h := strings.ToLower(routeID), CanonicalHost(host)
	for _, k := range c.InvertFailureHosts {
		if (r != "" && k == r) || k == h {
			return true
		}
	}
	return false
}

// Effective resolves the policy for one request.
func (c Config) Effective(host, routeID string) Effective {
	key, ok := c.lookupKey(host, routeID)
	e := Effective{Key: key, Mode: c.Mode, MaxBodyKB: c.MaxBodyKB, BodyTimeoutMS: c.BodyTimeoutMS, ParanoiaLevel: c.Coraza.ParanoiaLevel}
	if ok {
		h := c.Hosts[key]
		if h.Mode != ModeInherit && h.Mode != "" {
			e.Mode = h.Mode
		}
		if h.MaxBodyKB != 0 {
			e.MaxBodyKB = h.MaxBodyKB
		}
		if h.BodyTimeoutMS != 0 {
			e.BodyTimeoutMS = h.BodyTimeoutMS
		}
		if h.ParanoiaLevel != 0 {
			e.ParanoiaLevel = h.ParanoiaLevel
		}
	}
	e.FailClosed = c.FailClosed != c.inverted(host, routeID)
	return e
}

// ParanoiaLevels lists the distinct paranoia levels referenced by the config,
// i.e. the engines that must be precompiled.
func (c Config) ParanoiaLevels() []int {
	set := map[int]bool{c.Coraza.ParanoiaLevel: true}
	for _, h := range c.Hosts {
		if h.ParanoiaLevel != 0 {
			set[h.ParanoiaLevel] = true
		}
	}
	out := make([]int, 0, len(set))
	for pl := range set {
		out = append(out, pl)
	}
	sort.Ints(out)
	return out
}

// Policy derives the control-plane snapshot served to the Zoraxy core.
func (c Config) Policy() wire.Policy {
	p := wire.Policy{
		Mode:               c.Mode,
		FailClosed:         c.FailClosed,
		InvertFailureHosts: append([]string{}, c.InvertFailureHosts...),
		MaxBodyKB:          c.MaxBodyKB,
		BodyTimeoutMS:      c.BodyTimeoutMS,
		Hosts:              make(map[string]wire.HostPolicy, len(c.Hosts)),
	}
	for k, h := range c.Hosts {
		mode := h.Mode
		if mode == "" {
			mode = ModeInherit
		}
		p.Hosts[k] = wire.HostPolicy{Mode: mode, MaxBodyKB: h.MaxBodyKB, BodyTimeoutMS: h.BodyTimeoutMS}
	}
	return p.Normalized()
}

// Active reports whether the exception is in force at now.
func (e Exception) Active(now time.Time) bool { return now.Before(e.ExpiresAt) }

// Matches reports whether the exception applies to a request. Host scope is
// the exact route id or canonical host; path is exact unless it ends in "*".
func (e Exception) Matches(host, routeID, method, path string, now time.Time) bool {
	if !e.Active(now) {
		return false
	}
	if e.Host != strings.ToLower(routeID) && e.Host != CanonicalHost(host) {
		return false
	}
	if e.Method != "" && e.Method != method {
		return false
	}
	if e.Path != "" {
		if prefix, ok := strings.CutSuffix(e.Path, "*"); ok {
			if !strings.HasPrefix(path, prefix) {
				return false
			}
		} else if path != e.Path {
			return false
		}
	}
	return true
}
