package admin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/profiles"
	"zoraxy-waf-plugin/internal/service"
)

func registerProfiles(mux *http.ServeMux, s *service.Service) {
	mux.HandleFunc("/ui/api/profiles", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		out := []profiles.Profile{}
		for _, p := range profiles.All() {
			if (p.CRSPlugin == "" || s.Current().Engine == config.EngineCoraza) && s.Capabilities().RuleExclusions {
				out = append(out, p)
			}
		}
		service.JSON(w, out)
	})
	mux.HandleFunc("/ui/api/profiles/preview", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "GET") {
			return
		}
		p, err := s.PreviewProfile(r.URL.Query().Get("host"), r.URL.Query().Get("id"))
		if err != nil {
			http.Error(w, "Profile unavailable", 422)
			return
		}
		service.JSON(w, p)
	})
	mux.HandleFunc("/ui/api/profiles/change", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, "POST") {
			return
		}
		var req struct {
			Host           string `json:"host"`
			ID             string `json:"id"`
			Action         string `json:"action"`
			ConfirmMethods bool   `json:"confirm_methods"`
			Revision       uint64 `json:"revision"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil || dec.Decode(new(any)) != io.EOF {
			http.Error(w, "Invalid profile request", 400)
			return
		}
		before, _ := s.HostStatuses(0)
		open := map[string]bool{}
		for _, h := range before {
			if h.Host == req.Host {
				for _, f := range h.Findings {
					if f.Status == "open" {
						open[f.Key] = true
					}
				}
			}
		}
		var saved config.Config
		var err error
		switch req.Action {
		case "apply":
			saved, err = s.ApplyProfile(req.Host, req.ID, req.ConfirmMethods, req.Revision)
		case "remove":
			saved, err = s.RemoveProfile(req.Host, req.ID, req.Revision)
		case "dismiss":
			saved, err = s.DismissProfile(req.Host, req.ID, req.Revision)
		default:
			http.Error(w, "Unknown profile action", 400)
			return
		}
		if err != nil {
			code := 400
			if errors.Is(err, service.ErrProfileConflict) {
				code = 409
			}
			if errors.Is(err, engine.ErrUnsupported) {
				code = 422
			}
			http.Error(w, "Profile change rejected: "+safeConfigError(err), code)
			return
		}
		after, _ := s.HostStatuses(0)
		resolved := []string{}
		for _, h := range after {
			if h.Host == req.Host {
				for _, f := range h.Findings {
					if open[f.Key] && f.Status == "resolved" {
						resolved = append(resolved, f.Key)
					}
				}
			}
		}
		service.JSON(w, map[string]any{"config": publicConfig(saved), "resolved_keys": resolved})
	})
}
