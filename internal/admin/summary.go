package admin

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/events"
	"zoraxy-waf-plugin/internal/history"
	"zoraxy-waf-plugin/internal/service"
)

// Summary feeds the overview: every number carries its window so the UI never
// shows a bare counter (today vs. 7-day average, "last N events", ...).
type Summary struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Mode        string          `json:"mode"`
	Engine      string          `json:"engine"`
	Health      service.Health  `json:"health"`
	Stats       service.Stats   `json:"stats"`
	History     history.Summary `json:"history"`
	Window      Window          `json:"window"`
	Categories  []KV            `json:"categories"`
	TopHosts    []KV            `json:"top_hosts"`
	TopRules    []KV            `json:"top_rules"`
	TopIPs      []KV            `json:"top_ips"`
	Protection  Protection      `json:"protection"`
	Exceptions  ExceptionStats  `json:"exceptions"`
	HostsOff    []string        `json:"hosts_off"`
	HostsReport []string        `json:"hosts_report"`
	HostsBlock  []string        `json:"hosts_block"`
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
	Score int              `json:"score"`
	Items []ProtectionItem `json:"items"`
}

type ProtectionItem struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Weight int    `json:"weight"`
	Label  string `json:"label"`
	Hint   string `json:"hint"` // what to do when not OK, empty when OK
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
	out.Protection = protection(cfg, health, s.Events().Stats(), out)
	return out
}

func protection(cfg config.Config, h service.Health, feed events.Stats, sum Summary) Protection {
	var items []ProtectionItem
	add := func(id string, ok bool, weight int, label, hint, tab string) {
		if ok {
			hint = ""
		}
		items = append(items, ProtectionItem{ID: id, OK: ok, Weight: weight, Label: label, Hint: hint, Tab: tab})
	}
	add("engine", h.Engine.OK, 20, "Engine ready", "The inspection engine reports a problem: "+h.Engine.Detail, "settings")
	switch cfg.Mode {
	case config.ModeBlock:
		add("mode", true, 40, "Blocking attacks", "", "settings")
	case config.ModeReport:
		add("mode", false, 40, "Learning mode: attacks are recorded, not blocked",
			fmt.Sprintf("%d attacks in the last 7 days reached your sites. When the Learning tab shows no false positives, switch Default mode to Block.", sum.History.D7.Attacks()), "settings")
	default:
		add("mode", false, 40, "Inspection is off", "Requests are not inspected. Start with Report only, then Block.", "settings")
	}
	add("hosts", len(sum.HostsOff) == 0, 15, "No host switched off", fmt.Sprintf("Hosts without inspection: %v", sum.HostsOff), "hosts")
	add("exceptions", sum.Exceptions.Expired == 0, 10, "Exceptions tidy",
		fmt.Sprintf("%d expired exception(s) still listed; remove or renew them so the list stays reviewable.", sum.Exceptions.Expired), "exceptions")
	add("feed", feed.WriteErrors == 0 && feed.Dropped == 0, 15, "Event log healthy",
		fmt.Sprintf("JSONL feed: %d dropped, %d write errors. Check disk space and retention settings.", feed.Dropped, feed.WriteErrors), "settings")
	score := 0
	for _, it := range items {
		if it.OK {
			score += it.Weight
		}
	}
	return Protection{Score: score, Items: items}
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
	case sum.Mode == config.ModeReport:
		w.Headline = "Learning mode (report only)"
	default:
		w.State, w.Headline = "off", "Inspection off"
	}
	w.Sub = fmt.Sprintf("Protection %d %% · %s", sum.Protection.Score, sum.Health.EngineName)
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
		WidgetMetric{Label: "Recorded only (24 h)", Value: strconv.FormatUint(hist.H24.WouldBlock, 10), Note: "learning mode / report hosts"},
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
