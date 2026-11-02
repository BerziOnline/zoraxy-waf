package admin

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/events"
	"zoraxy-waf-plugin/internal/history"
	"zoraxy-waf-plugin/internal/service"
)

// Summary feeds the overview: every number carries its window so the UI never
// shows a bare counter (today vs. 7-day average, "last N events", ...).
type Summary struct {
	GeneratedAt time.Time               `json:"generated_at"`
	Mode        string                  `json:"mode"`
	Engine      string                  `json:"engine"`
	Health      service.Health          `json:"health"`
	Stats       service.Stats           `json:"stats"`
	History     history.Summary         `json:"history"`
	Window      Window                  `json:"window"`
	Categories  []KV                    `json:"categories"`
	TopHosts    []KV                    `json:"top_hosts"`
	TopRules    []KV                    `json:"top_rules"`
	TopIPs      []KV                    `json:"top_ips"`
	Protection  Protection              `json:"protection"`
	Exceptions  ExceptionStats          `json:"exceptions"`
	HostsOff    []string                `json:"hosts_off"`
	HostsReport []string                `json:"hosts_report"`
	HostsBlock  []string                `json:"hosts_block"`
	Learning    service.LearningSummary `json:"learning"`
	Uncovered   []string                `json:"uncovered"` // Zoraxy routes no tag sends through the WAF
}

// Window describes which events the top lists were computed from.
type Window struct {
	Events   int       `json:"events"`    // events in the live ring (attacks, errors, oversize)
	RingSize int       `json:"ring_size"` // capacity of the ring
	Oldest   time.Time `json:"oldest"`    // zero when empty
}

// KV is one ranking row.
type KV struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"`
	Count int    `json:"count"`
}

// Protection mirrors Wordfence's status circle: a score out of 100 made of
// named, actionable checks; each check links to the tab that fixes it.
type Protection struct {
	Items []ProtectionItem `json:"items"`
}

type ProtectionItem struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Label  string `json:"label"`
	Hint   string `json:"hint,omitempty"`   // detail when not OK
	Action string `json:"action,omitempty"` // button label when not OK
	Info   bool   `json:"info,omitempty"`   // not OK, but possibly on purpose (shown neutral)
	Tab    string `json:"tab"`
}

type ExceptionStats struct {
	Active     int `json:"active"`
	Expiring7d int `json:"expiring_7d"`
	Expired    int `json:"expired"`
}

func top(counts map[string]int, labels map[string]string, n int) []KV {
	out := make([]KV, 0, len(counts))
	for k, v := range counts {
		out = append(out, KV{Key: k, Label: labels[k], Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func summarize(s *service.Service, now time.Time, loc *time.Location) Summary {
	cfg := s.Current()
	health := s.Health()
	out := Summary{GeneratedAt: now, Mode: cfg.Mode, Engine: cfg.Engine, Health: health, Stats: s.Stats(),
		History: s.History().Summary(loc), HostsOff: []string{}, HostsReport: []string{}, HostsBlock: []string{}}
	all := s.Events().List(events.Filter{Limit: cfg.Events.RingSize})
	out.Window = Window{Events: len(all), RingSize: cfg.Events.RingSize}
	if len(all) > 0 {
		out.Window.Oldest = all[len(all)-1].Time
	}
	cats, hosts, rules, ips := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	ruleText := map[string]string{}
	for _, ev := range all {
		if ev.Action != events.ActionBlocked && ev.Action != events.ActionWouldBlock {
			continue
		}
		cats[ev.Category()]++
		key := ev.RouteID
		if key == "" {
			key = ev.Host
		}
		hosts[key]++
		if ev.ClientIP != "" {
			ips[ev.ClientIP]++
		}
		for _, m := range ev.Matches {
			if events.Category(m.RuleID) == "" {
				continue // scoring/correlation rules are not the attack
			}
			id := strconv.Itoa(m.RuleID)
			rules[id]++
			if ruleText[id] == "" {
				ruleText[id] = m.Message
			}
			break // one detection rule per event, the first that fired
		}
	}
	out.Categories = top(cats, nil, 8)
	out.TopHosts = top(hosts, nil, 5)
	out.TopRules = top(rules, ruleText, 5)
	out.TopIPs = top(ips, nil, 5)
	for host, h := range cfg.Hosts {
		switch h.Mode {
		case config.ModeOff:
			out.HostsOff = append(out.HostsOff, host)
		case config.ModeReport:
			out.HostsReport = append(out.HostsReport, host)
		case config.ModeBlock:
			out.HostsBlock = append(out.HostsBlock, host)
		case config.ModeLearn:
			out.HostsReport = append(out.HostsReport, host)
		}
	}
	sort.Strings(out.HostsOff)
	sort.Strings(out.HostsReport)
	sort.Strings(out.HostsBlock)
	for _, ex := range cfg.Exceptions {
		switch {
		case !ex.ExpiresAt.After(now):
			out.Exceptions.Expired++
		case ex.ExpiresAt.Before(now.Add(7 * 24 * time.Hour)):
			out.Exceptions.Active++
			out.Exceptions.Expiring7d++
		default:
			out.Exceptions.Active++
		}
	}
	rows, _ := s.HostStatuses(0) // cached route list; the overview never waits for Zoraxy
	out.Learning = service.SummarizeLearning(rows)
	out.Uncovered = []string{}
	for _, r := range rows {
		if r.InZoraxy && !r.Protected && !r.Disabled && !r.Wildcard {
			out.Uncovered = append(out.Uncovered, r.Host)
		}
	}
	out.Protection = protection(cfg, health, s.Events().Stats(), out)
	return out
}

func protection(cfg config.Config, h service.Health, feed events.Stats, sum Summary) Protection {
	var items []ProtectionItem
	// add records one status line. A line that is not OK names the action
	// (button label) and the tab where the user does it.
	add := func(id string, ok bool, label, hint, action, tab string) {
		if ok {
			hint, action = "", ""
		}
		items = append(items, ProtectionItem{ID: id, OK: ok, Label: label, Hint: hint, Action: action, Tab: tab})
	}
	if h.Engine.OK {
		add("engine", true, "Engine ready", "", "", "settings")
	} else {
		add("engine", false, "Engine problem", h.Engine.Detail, "Settings", "settings")
	}
	switch cfg.Mode {
	case config.ModeBlock:
		add("mode", true, "Blocking attacks", "", "", "settings")
	case config.ModeLearn:
		l := sum.Learning
		switch {
		case l.Open > 0:
			add("mode", false, plural(l.Open, "open finding keeps a host", "open findings keep hosts")+" learning", "", "Review findings", "learning")
		case l.Learning == 0 && l.Blocking > 0:
			add("mode", true, fmt.Sprintf("All %d hosts block", l.Hosts), "", "", "learning")
		default:
			add("mode", true, fmt.Sprintf("Learning: %d of %d hosts block, no open findings", l.Blocking, l.Hosts), "", "", "learning")
		}
	case config.ModeReport:
		add("mode", false, "Report only: nothing is blocked",
			fmt.Sprintf("%d attacks in the last 7 days reached your sites.", sum.History.D7.Attacks()), "Change default mode", "settings")
	default:
		if cfg.SetupRequired() {
			add("mode", false, "Inspection is off", "", "Turn on", "overview")
		} else {
			add("mode", false, "Inspection is off", "", "Change default mode", "settings")
		}
	}
	if len(sum.HostsOff) == 0 {
		add("hosts", true, "No host switched off", "", "", "hosts")
	} else {
		add("hosts", false, "Not inspected: "+strings.Join(sum.HostsOff, ", "), "", "Hosts", "hosts")
	}
	if n := len(sum.Uncovered); n > 0 {
		list := sum.Uncovered
		if n > 3 {
			list = append(append([]string{}, list[:3]...), fmt.Sprintf("+%d", n-3))
		}
		items = append(items, ProtectionItem{ID: "coverage", Label: "Not inspected (no WAF tag in Zoraxy): " + strings.Join(list, ", "), Action: "Hosts", Tab: "hosts", Info: true})
	}
	// Only shown when Zoraxy does not deliver the body the WAF is set to inspect.
	if h.BodiesMissing > 0 {
		add("bodies", false, "Request bodies are not inspected",
			"Zoraxy sends no request bodies to the WAF. Update Zoraxy to a version with dynamic_capture_sniff_body_kb, then restart it.", "", "settings")
	} else if h.ZoraxyBodyKB > 0 {
		add("bodies", false, fmt.Sprintf("Zoraxy sends only %d KiB of each request body", h.ZoraxyBodyKB),
			"Zoraxy reads the body size when it starts. Restart Zoraxy to use the size from the settings.", "", "settings")
	}
	if sum.Exceptions.Expired == 0 {
		add("exceptions", true, "No expired exceptions", "", "", "exceptions")
	} else {
		add("exceptions", false, plural(sum.Exceptions.Expired, "expired exception", "expired exceptions"), "", "Exceptions", "exceptions")
	}
	if feed.WriteErrors == 0 && feed.Dropped == 0 {
		add("feed", true, "Event log healthy", "", "", "settings")
	} else {
		add("feed", false, fmt.Sprintf("Event log: %d dropped, %d write errors", feed.Dropped, feed.WriteErrors), "Check the disk space of the Zoraxy host.", "Settings", "settings")
	}
	return Protection{Items: items}
}

// plural formats "1 thing" or "n things".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Widget is the compact card Zoraxy renders on its own status page (IntroSpect
// DashboardWidget). Generic shape: the core knows nothing about WAFs.
type Widget struct {
	Title    string         `json:"title"`
	State    string         `json:"state"` // ok | warn | off
	Headline string         `json:"headline"`
	Sub      string         `json:"sub"`
	Metrics  []WidgetMetric `json:"metrics"`
	Bars     []WidgetBar    `json:"bars"`
	Spark    []int          `json:"spark"` // attacks per hour, last 24 h, oldest first
}

type WidgetMetric struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

type WidgetBar struct {
	Label string `json:"label"`
	Value int    `json:"value"`
}

func widget(sum Summary) Widget {
	w := Widget{Title: "Zoraxy WAF", State: "warn", Metrics: []WidgetMetric{}, Bars: []WidgetBar{}, Spark: []int{}}
	hist := sum.History
	switch {
	case !sum.Health.Engine.OK:
		w.Headline = "Engine problem"
	case sum.Mode == config.ModeBlock:
		w.State, w.Headline = "ok", "Blocking attacks"
	case sum.Mode == config.ModeLearn:
		w.Headline = fmt.Sprintf("Learning: %d of %d hosts block", sum.Learning.Blocking, sum.Learning.Hosts)
		if sum.Learning.Learning == 0 && sum.Learning.Blocking > 0 {
			w.State, w.Headline = "ok", "Blocking attacks"
		}
	case sum.Mode == config.ModeReport:
		w.Headline = "Report only (never blocks)"
	default:
		w.State, w.Headline = "off", "Inspection off"
	}
	w.Sub = sum.Health.EngineName
	if sum.Health.Engine.RuleSet != "" {
		w.Sub += " · " + sum.Health.Engine.RuleSet
	}
	avg := "no 7-day reference yet"
	if hist.DaysKnown > 0 {
		days := hist.DaysKnown
		if days > 7 {
			days = 7
		}
		// Complete days only: today is excluded from the average.
		prev := hist.D7.Attacks() - hist.Today.Attacks()
		avg = fmt.Sprintf("Ø %.1f per day (last %d full days)", float64(prev)/float64(days), days)
	}
	w.Metrics = append(w.Metrics,
		WidgetMetric{Label: "Attacks today", Value: strconv.FormatUint(hist.Today.Attacks(), 10), Note: avg},
		WidgetMetric{Label: "Blocked (24 h)", Value: strconv.FormatUint(hist.H24.Blocked, 10), Note: "stopped before routing"},
		WidgetMetric{Label: "Not blocked (24 h)", Value: strconv.FormatUint(hist.H24.WouldBlock, 10), Note: "learning or report only"},
		WidgetMetric{Label: "Errors (24 h)", Value: strconv.FormatUint(hist.H24.Error+hist.H24.Oversize, 10), Note: fmt.Sprintf("%s clean requests allowed", strconv.FormatUint(hist.H24.Allowed, 10))})
	for i, c := range sum.Categories {
		if i == 4 {
			break
		}
		w.Bars = append(w.Bars, WidgetBar{Label: c.Key, Value: c.Count})
	}
	for _, p := range hist.Hours {
		w.Spark = append(w.Spark, int(p.Attacks()))
	}
	return w
}
