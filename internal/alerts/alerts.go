// Package alerts pushes a few operationally relevant conditions to external
// monitoring/reporting systems. Design rules:
//
//   - Off by default and free when off: the request path only increments an
//     atomic counter; everything else runs in one background goroutine.
//   - Sinks are pluggable behind one interface. Two formats cover most
//     receivers: a generic JSON webhook (any monitoring system, n8n, custom
//     receivers) and a "text" webhook compatible with Mattermost and Slack
//     incoming webhooks. New formats are one function each.
//   - Each condition has a key and a cooldown, so a flapping engine or a long
//     attack never floods the receiver.
//   - Delivery is best effort with a short timeout; failures are counted and
//     shown in the UI, never retried in a loop and never block inspection.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Settings is the persisted configuration (part of config.Config).
type Settings struct {
	Enabled bool   `json:"enabled"`
	Sinks   []Sink `json:"sinks"`
	// Burst fires when at least BurstCount attacks (blocked or recorded) were
	// seen within BurstWindowMin minutes.
	BurstCount     int `json:"burst_count"`
	BurstWindowMin int `json:"burst_window_min"`
	// ExceptionExpiryDays warns this many days before an exception expires (0 = off).
	ExceptionExpiryDays int `json:"exception_expiry_days"`
	// CooldownMin is the minimum gap between two alerts with the same key.
	CooldownMin int `json:"cooldown_min"`
	// EngineHealth fires when the engine reports not ok (and once when it recovers).
	EngineHealth bool `json:"engine_health"`
}

// Sink is one receiver. Format "json" posts the Alert as JSON; "text" posts
// {"text": "..."} as Mattermost and Slack incoming webhooks expect.
type Sink struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Format string `json:"format"`
	URL    string `json:"url"`
	// Token is sent as "Authorization: Bearer <token>" when set (json sinks).
	Token string `json:"token,omitempty"`
}

// Alert is the payload every sink receives (json sinks verbatim).
type Alert struct {
	Version  int               `json:"v"`
	Time     time.Time         `json:"time"`
	Source   string            `json:"source"`
	Key      string            `json:"key"`      // stable id of the condition, e.g. "burst", "engine", "exception:<id>"
	Severity string            `json:"severity"` // "warning", "critical", "info"
	Title    string            `json:"title"`
	Message  string            `json:"message"`
	Fields   map[string]string `json:"fields,omitempty"`
}

// Defaults are the fresh-install values: configured but disabled.
func Defaults() Settings {
	return Settings{BurstCount: 50, BurstWindowMin: 5, ExceptionExpiryDays: 3, CooldownMin: 30, EngineHealth: true}
}

var Formats = map[string]bool{"json": true, "text": true}

// Validate rejects unusable settings; sinks need an https/http URL.
func (s Settings) Validate() error {
	if s.BurstCount < 1 || s.BurstCount > 1_000_000 {
		return errors.New("alerts: burst_count must be 1..1000000")
	}
	if s.BurstWindowMin < 1 || s.BurstWindowMin > 1440 {
		return errors.New("alerts: burst_window_min must be 1..1440")
	}
	if s.ExceptionExpiryDays < 0 || s.ExceptionExpiryDays > 366 {
		return errors.New("alerts: exception_expiry_days must be 0..366")
	}
	if s.CooldownMin < 1 || s.CooldownMin > 10080 {
		return errors.New("alerts: cooldown_min must be 1..10080")
	}
	if len(s.Sinks) > 20 {
		return errors.New("alerts: at most 20 sinks")
	}
	seen := map[string]bool{}
	for _, k := range s.Sinks {
		switch {
		case k.ID == "" || len(k.ID) > 64 || seen[k.ID]:
			return errors.New("alerts: sink id missing or duplicate")
		case len(k.Name) > 64:
			return errors.New("alerts: sink name too long")
		case !Formats[k.Format]:
			return errors.New("alerts: sink format must be json or text")
		case !(strings.HasPrefix(k.URL, "https://") || strings.HasPrefix(k.URL, "http://")) || len(k.URL) > 2048 || strings.ContainsAny(k.URL, " \r\n"):
			return errors.New("alerts: sink url must be an http(s) URL")
		case len(k.Token) > 512:
			return errors.New("alerts: sink token too long")
		}
		seen[k.ID] = true
	}
	if s.Enabled && len(s.Sinks) == 0 {
		return errors.New("alerts: enabled without a sink")
	}
	return nil
}

// Clone copies the settings including the sink slice.
func (s Settings) Clone() Settings {
	s.Sinks = append([]Sink{}, s.Sinks...)
	return s
}

// Public strips tokens for the UI.
func (s Settings) Public() Settings {
	s = s.Clone()
	for i := range s.Sinks {
		if s.Sinks[i].Token != "" {
			s.Sinks[i].Token = "stored"
		}
	}
	return s
}

// Stats are the delivery counters shown in the UI.
type Stats struct {
	Sent, Failed uint64
	LastError    string
	LastSentAt   time.Time
}

// Probe is what the notifier observes every tick (supplied by the service).
type Probe struct {
	EngineOK     bool
	EngineDetail string
	// Exceptions maps exception id → (label, expiry).
	Exceptions map[string]Expiring
}

type Expiring struct {
	Label     string
	ExpiresAt time.Time
}

// Notifier evaluates conditions and delivers alerts.
type Notifier struct {
	source string
	now    func() time.Time
	client *http.Client

	attacks atomic.Uint64 // incremented from the request path only

	mu        sync.Mutex
	settings  Settings
	lastSent  map[string]time.Time
	samples   []sample // attack counter samples for the burst window
	engineOK  *bool    // nil until first probe
	stats     Stats
	lastError string
}

type sample struct {
	at    time.Time
	count uint64
}

func New(source string, now func() time.Time) *Notifier {
	if now == nil {
		now = time.Now
	}
	return &Notifier{source: source, now: now, client: &http.Client{Timeout: 5 * time.Second}, lastSent: map[string]time.Time{}}
}

// Apply installs new settings (called under the service's apply lock).
func (n *Notifier) Apply(s Settings) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.settings = s.Clone()
}

// RecordAttack is the only request-path call: one atomic add.
func (n *Notifier) RecordAttack() { n.attacks.Add(1) }

// Stats returns delivery counters.
func (n *Notifier) Stats() Stats {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.stats
}

// Tick evaluates all conditions once; the service calls it periodically.
func (n *Notifier) Tick(ctx context.Context, p Probe) {
	n.mu.Lock()
	s := n.settings
	now := n.now()
	total := n.attacks.Load()
	n.samples = append(n.samples, sample{at: now, count: total})
	window := time.Duration(s.BurstWindowMin) * time.Minute
	// Keep the newest sample that is at least one window old as the baseline.
	for len(n.samples) > 1 && now.Sub(n.samples[1].at) >= window {
		n.samples = n.samples[1:]
	}
	var pending []Alert
	if s.Enabled {
		if delta := total - n.samples[0].count; s.BurstCount > 0 && delta >= uint64(s.BurstCount) && n.samples[0].at != now {
			pending = append(pending, Alert{Key: "burst", Severity: "critical", Title: "Attack burst",
				Message: fmt.Sprintf("%d attacks in the last %d minutes (threshold %d).", delta, s.BurstWindowMin, s.BurstCount),
				Fields:  map[string]string{"attacks": fmt.Sprint(delta), "window_min": fmt.Sprint(s.BurstWindowMin)}})
		}
		if s.EngineHealth {
			if n.engineOK == nil || *n.engineOK != p.EngineOK {
				if n.engineOK != nil || !p.EngineOK { // first probe only alerts when unhealthy
					if p.EngineOK {
						pending = append(pending, Alert{Key: "engine", Severity: "info", Title: "Engine recovered", Message: "The inspection engine is healthy again."})
					} else {
						pending = append(pending, Alert{Key: "engine", Severity: "critical", Title: "Engine unhealthy", Message: "The inspection engine reports a problem: " + p.EngineDetail, Fields: map[string]string{"detail": p.EngineDetail}})
					}
				}
			}
		}
		if s.ExceptionExpiryDays > 0 {
			ids := make([]string, 0, len(p.Exceptions))
			for id := range p.Exceptions {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				e := p.Exceptions[id]
				if left := e.ExpiresAt.Sub(now); left > 0 && left <= time.Duration(s.ExceptionExpiryDays)*24*time.Hour {
					pending = append(pending, Alert{Key: "exception:" + id, Severity: "warning", Title: "Exception expires soon",
						Message: fmt.Sprintf("%s expires in %s; the rule applies again afterwards.", e.Label, humanDuration(left)),
						Fields:  map[string]string{"exception": id, "expires_at": e.ExpiresAt.UTC().Format(time.RFC3339)}})
				}
			}
		}
	}
	ok := p.EngineOK
	n.engineOK = &ok
	// Cooldown per key; state transitions of the engine always pass.
	var send []Alert
	for _, a := range pending {
		if last, seen := n.lastSent[a.Key]; seen && a.Key != "engine" && now.Sub(last) < time.Duration(s.CooldownMin)*time.Minute {
			continue
		}
		n.lastSent[a.Key] = now
		send = append(send, a)
	}
	sinks := append([]Sink{}, s.Sinks...)
	n.mu.Unlock()
	for _, a := range send {
		n.deliver(ctx, sinks, a)
	}
}

// Test sends one informational alert to every configured sink immediately.
func (n *Notifier) Test(ctx context.Context) error {
	n.mu.Lock()
	sinks := append([]Sink{}, n.settings.Sinks...)
	n.mu.Unlock()
	if len(sinks) == 0 {
		return errors.New("no sink configured")
	}
	return n.deliver(ctx, sinks, Alert{Key: "test", Severity: "info", Title: "Test alert", Message: "Zoraxy WAF alerting works. This message was sent manually from the plugin UI."})
}

// deliver posts to every sink and returns the last failure (nil when all
// receivers accepted the alert).
func (n *Notifier) deliver(ctx context.Context, sinks []Sink, a Alert) error {
	a.Version, a.Time, a.Source = 1, n.now().UTC(), n.source
	var failed error
	for _, k := range sinks {
		err := n.post(ctx, k, a)
		n.mu.Lock()
		if err != nil {
			n.stats.Failed++
			n.stats.LastError = fmt.Sprintf("%s: %v", k.Name, err)
			failed = errors.New(n.stats.LastError)
		} else {
			n.stats.Sent++
			n.stats.LastSentAt = n.now()
			n.stats.LastError = ""
		}
		n.mu.Unlock()
	}
	return failed
}

func (n *Notifier) post(ctx context.Context, k Sink, a Alert) error {
	var body []byte
	switch k.Format {
	case "text":
		body, _ = json.Marshal(map[string]string{"text": fmt.Sprintf("**%s – %s** (%s)\n%s", a.Source, a.Title, a.Severity, a.Message)})
	default:
		body, _ = json.Marshal(a)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", k.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "zoraxy-waf-alerts/1")
	if k.Token != "" {
		req.Header.Set("Authorization", "Bearer "+k.Token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("receiver answered %d", resp.StatusCode)
	}
	return nil
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
}
