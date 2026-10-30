// Package admin serves the embedded Zoraxy plugin UI and its private API.
package admin

import (
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"io/fs"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/events"
	"zoraxy-waf-plugin/internal/service"
)

//go:embed web/*
var web embed.FS
var errConflict = errors.New("configuration changed; reload before saving")

func publicConfig(c config.Config) config.Config {
	c.CrowdSec.APIKey = ""
	c.Alerts = c.Alerts.Public()
	return c
}

// keepSinkTokens restores stored sink tokens the UI never saw ("stored" or empty).
func keepSinkTokens(c *config.Config, old config.Config) {
	stored := map[string]string{}
	for _, k := range old.Alerts.Sinks {
		stored[k.ID] = k.Token
	}
	for i, k := range c.Alerts.Sinks {
		if k.Token == "stored" || k.Token == "" {
			c.Alerts.Sinks[i].Token = stored[k.ID]
		}
	}
}

// eventRow is an event as listed in the UI: the stored record plus the
// derived attack category, so the table and the overview name attacks alike.
type eventRow struct {
	events.Event
	Category string `json:"category"`
}

func Handler(s *service.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ui/api/state", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		c := s.Current()
		service.JSON(w, map[string]any{"config": publicConfig(c), "api_key_set": c.CrowdSec.APIKey != "", "capabilities": s.Capabilities(), "health": s.Health(), "stats": s.Stats(), "event_stats": s.Events().Stats(), "load_error": s.LoadError(), "event_settings_restart_required": true, "gc_percent": s.GCPercent(), "gc_start_percent": s.GCStartPercent(), "cpu_cores": runtime.GOMAXPROCS(0), "alert_stats": s.Alerts().Stats()})
	})
	mux.HandleFunc("/ui/api/summary", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		service.JSON(w, summarize(s, time.Now(), time.Local))
	})
	mux.HandleFunc("/ui/api/widget", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		service.JSON(w, widget(summarize(s, time.Now(), time.Local)))
	})
	mux.HandleFunc("/ui/api/config", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "PUT") {
			return
		}
		var c config.Config
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			http.Error(w, "Invalid configuration JSON", 400)
			return
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			http.Error(w, "Trailing configuration data", 400)
			return
		}
		saved, err := s.Apply(func(old *config.Config) error {
			if c.Revision != old.Revision {
				return errConflict
			}
			if c.CrowdSec.APIKey == "" {
				c.CrowdSec.APIKey = old.CrowdSec.APIKey
			}
			keepSinkTokens(&c, *old)
			// The revision is owned by the service, never by the client.
			*old = c.Clone()
			return nil
		})
		if err != nil {
			code := 400
			if errors.Is(err, errConflict) {
				code = 409
			}
			if errors.Is(err, engine.ErrUnsupported) {
				code = 422
			}
			http.Error(w, "Configuration rejected: "+safeConfigError(err), code)
			return
		}
		service.JSON(w, publicConfig(saved))
	})
	mux.HandleFunc("/ui/api/alerts/test", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "POST") {
			return
		}
		if err := s.Alerts().Test(r.Context()); err != nil {
			http.Error(w, "Test alert failed: "+err.Error(), 502)
			return
		}
		service.JSON(w, s.Alerts().Stats())
	})
	mux.HandleFunc("/ui/api/changes", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		list, err := s.Changes(50)
		if err != nil {
			http.Error(w, "Change history unreadable", 500)
			return
		}
		if list == nil {
			list = []config.PublicHistoryEntry{}
		}
		service.JSON(w, list)
	})
	mux.HandleFunc("/ui/api/changes/revert", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "POST") {
			return
		}
		var req struct {
			Revision uint64 `json:"revision"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil || req.Revision == 0 {
			http.Error(w, "Invalid revert request", 400)
			return
		}
		saved, err := s.Revert(req.Revision)
		if err != nil {
			code := 400
			if errors.Is(err, engine.ErrUnsupported) {
				code = 422
			}
			http.Error(w, "Rollback rejected: "+safeConfigError(err), code)
			return
		}
		service.JSON(w, publicConfig(saved))
	})
	mux.HandleFunc("/ui/api/events", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		f, err := filter(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		list := s.Events().List(f)
		out := make([]eventRow, 0, len(list))
		for _, ev := range list {
			out = append(out, eventRow{Event: ev, Category: ev.Category()})
		}
		service.JSON(w, out)
	})
	mux.HandleFunc("/ui/api/export", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		f, err := filter(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="waf-events.jsonl"`)
		s.Events().Export(w, f)
	})
	mux.HandleFunc("/ui/api/events/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/ui/api/events/")
		id, ok := strings.CutSuffix(id, "/suggestions")
		if !ok || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		ev, ok := s.Events().Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if !s.Capabilities().RuleExclusions {
			http.Error(w, "Engine does not support scoped rule exclusions", 422)
			return
		}
		service.JSON(w, events.Suggest(ev))
	})
	assets, _ := fs.Sub(web, "web")
	files := http.StripPrefix("/ui/", http.FileServer(http.FS(assets)))
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		if r.URL.Path == "/ui/" || r.URL.Path == "/ui/index.html" {
			b, _ := web.ReadFile("web/index.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, strings.ReplaceAll(string(b), "{{.csrfToken}}", html.EscapeString(r.Header.Get("X-Zoraxy-Csrf"))))
			return
		}
		files.ServeHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'self'")
		// Zoraxy's authenticated plugin proxy overwrites this header with the
		// session CSRF token. It is not an authentication boundary against local
		// processes; the plugin listens only on loopback.
		trusted := r.Header.Get("X-Zoraxy-Csrf")
		if trusted == "" || trusted == "missing-csrf-token" {
			http.Error(w, "Open this plugin through the authenticated Zoraxy UI", 403)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			echo := r.Header.Get("X-WAF-CSRF")
			if !sameCSRFToken(trusted, echo) {
				http.Error(w, "CSRF verification failed", 403)
				return
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				http.Error(w, "JSON required", 415)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

// sameCSRFToken compares the underlying gorilla/csrf session token. Its
// 64-byte wire format is a 32-byte mask followed by mask XOR session token;
// comparing masked strings directly rejects every real Zoraxy UI mutation.
func sameCSRFToken(trusted, echo string) bool {
	if echo == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(trusted), []byte(echo)) == 1 {
		return true // Exact echo also supports the SDK's disposable dev server.
	}
	unmask := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(b) != 64 {
			return nil
		}
		for i := 0; i < 32; i++ {
			b[i] ^= b[i+32]
		}
		return b[:32]
	}
	a, b := unmask(trusted), unmask(echo)
	return a != nil && b != nil && subtle.ConstantTimeCompare(a, b) == 1
}

func safeConfigError(err error) string {
	// Validation strings contain configuration keys/IDs but not credentials.
	// Compilation/IO/remote errors are intentionally not returned to clients.
	if errors.Is(err, errConflict) {
		return err.Error()
	}
	return "check field limits, host identities, engine settings and exception scope/expiry; previous configuration remains active"
}
func method(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method != want {
		w.Header().Set("Allow", want)
		http.Error(w, want+" required", 405)
		return false
	}
	return true
}
func filter(r *http.Request) (events.Filter, error) {
	q := r.URL.Query()
	f := events.Filter{Host: q.Get("host"), Action: q.Get("action"), ClientIP: q.Get("client_ip"), Text: q.Get("text"), Limit: 200}
	if x := q.Get("rule_id"); x != "" {
		v, e := strconv.Atoi(x)
		if e != nil || v < 1 {
			return f, errors.New("Invalid rule ID")
		}
		f.RuleID = v
	}
	if x := q.Get("limit"); x != "" {
		v, e := strconv.Atoi(x)
		if e != nil || v < 1 || v > 10000 {
			return f, errors.New("Limit must be 1-10000")
		}
		f.Limit = v
	}
	if x := q.Get("since"); x != "" {
		v, e := time.Parse(time.RFC3339, x)
		if e != nil {
			return f, errors.New("Invalid since timestamp")
		}
		f.Since = v
	}
	return f, nil
}
