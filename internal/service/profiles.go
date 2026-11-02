package service

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/crsplugins"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/events"
	"zoraxy-waf-plugin/internal/learning"
	"zoraxy-waf-plugin/internal/profiles"
)

var ErrProfileConflict = errors.New("configuration changed; review the profile again")
var errProfileUnchanged = errors.New("profile already applied")

type ProfileSuggestion struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  int    `json:"version"`
	Evidence string `json:"evidence"`
}
type ProfileState struct {
	config.AppliedProfile
	Name            string `json:"name"`
	Modified        bool   `json:"modified"`
	UpdateAvailable bool   `json:"update_available"`
	Inactive        bool   `json:"inactive,omitempty"`
}
type ProfilePreview struct {
	Revision      uint64             `json:"revision"`
	Host          string             `json:"host"`
	Profile       profiles.Profile   `json:"profile"`
	MethodsBefore []string           `json:"methods_before"`
	MethodsAfter  []string           `json:"methods_after"`
	Added         []config.Exception `json:"added"`
	Removed       []config.Exception `json:"removed"`
	Unchanged     bool               `json:"unchanged"`
	PluginBefore  string             `json:"plugin_before,omitempty"`
	PluginAfter   string             `json:"plugin_after,omitempty"`
}

func profileSource(id string, version int) string { return fmt.Sprintf("profile:%s@%d", id, version) }

// ownsException: a profile owns exactly the exceptions with its source on its
// own host. An exception an admin moved to another host belongs to that host
// from then on and is never removed with the profile of the first one.
func ownsException(_ config.HostOverride, host, id string, ex config.Exception) bool {
	return sourceIs(ex.Source, id) && ex.Host == host
}
func sourceIs(source, id string) bool { return strings.HasPrefix(source, "profile:"+id+"@") }
func profileExceptions(host string, p profiles.Profile, now time.Time) []config.Exception {
	out := []config.Exception{}
	for _, ex := range p.Exceptions {
		for _, id := range ex.Rules {
			out = append(out, config.Exception{RuleID: id, Host: host, Method: ex.Method, Path: ex.Path, Argument: ex.Argument, Reason: fmt.Sprintf("%s v%d: %s", p.Name, p.Version, ex.Reason), Source: profileSource(p.ID, p.Version), CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(config.MaxExceptionLife)})
		}
	}
	return out
}
func sameException(a, b config.Exception) bool {
	return a.RuleID == b.RuleID && a.Host == b.Host && a.Method == b.Method && a.Path == b.Path && a.Argument == b.Argument && a.Source == b.Source && a.Reason == b.Reason
}
func profilePreview(c config.Config, host string, p profiles.Profile, now time.Time) ProfilePreview {
	before := append([]string{}, c.Hosts[host].Methods...)
	after := append([]string{}, before...)
	extra, _ := p.ExtraMethods()
	for _, m := range extra {
		if !slices.Contains(after, m) {
			after = append(after, m)
		}
	}
	out := ProfilePreview{Revision: c.Revision, Host: host, Profile: p, MethodsBefore: before, MethodsAfter: after, Added: []config.Exception{}, Removed: []config.Exception{}}
	out.PluginAfter = crsplugins.Commit(p.CRSPlugin)
	for _, ap := range c.Hosts[host].Profiles {
		if ap.ID == p.ID {
			out.PluginBefore = ap.PluginCommit
		}
		// A modified or expired profile is not "unchanged": applying it again
		// restores exactly the catalogue scopes and a fresh expiry.
		if ap.ID == p.ID && ap.Version == p.Version && ap.PluginCommit == out.PluginAfter && !profileModified(c, host, ap, p, now) {
			out.Unchanged = true
			return out
		}
	}
	expected := profileExceptions(host, p, now)
	for _, ex := range c.Exceptions {
		if ownsException(c.Hosts[host], host, p.ID, ex) {
			out.Removed = append(out.Removed, ex)
		}
	}
	// An update is a replacement of exactly this profile's owned scopes. Show
	// full old and new entries so even changes to a reason/field are reviewable.
	out.Added = expected
	return out
}
func (s *Service) PreviewProfile(host, id string) (ProfilePreview, error) {
	if !config.ValidKey(host) || host == "/" || strings.ContainsAny(host, "*") {
		return ProfilePreview{}, errors.New("choose an exact host")
	}
	p, ok := profiles.Get(id)
	if !ok {
		return ProfilePreview{}, errors.New("unknown profile")
	}
	c := s.Current()
	if p.CRSPlugin != "" && c.Engine != config.EngineCoraza || !s.Capabilities().RuleExclusions {
		return ProfilePreview{}, engine.ErrUnsupported
	}
	return profilePreview(c, host, p, s.opts.Now()), nil
}
func (s *Service) ApplyProfile(host, id string, confirmMethods bool, revision uint64) (config.Config, error) {
	preview, err := s.PreviewProfile(host, id)
	if err != nil {
		return config.Config{}, err
	}
	p := preview.Profile
	var unchanged config.Config
	saved, err := s.ApplyNote(fmt.Sprintf("Applied service profile %s v%d to %s", p.Name, p.Version, host), func(c *config.Config) error {
		if c.Revision != revision {
			return ErrProfileConflict
		}
		pr := profilePreview(*c, host, p, s.opts.Now())
		if pr.Unchanged {
			unchanged = c.Clone()
			return errProfileUnchanged
		}
		if len(pr.MethodsAfter) > len(pr.MethodsBefore) && !confirmMethods {
			return errors.New("confirm the additional methods")
		}
		h := c.Hosts[host]
		if h.Mode == "" {
			h.Mode = config.ModeInherit
		}
		h.Methods = pr.MethodsAfter
		h.Profiles = slices.DeleteFunc(h.Profiles, func(ap config.AppliedProfile) bool { return ap.ID == id })
		owned := []string{}
		for i := range pr.Added {
			pr.Added[i].ID = events.NewID()
			owned = append(owned, pr.Added[i].ID)
		}
		h.Profiles = append(h.Profiles, config.AppliedProfile{ID: id, Version: p.Version, ExceptionIDs: owned, PluginCommit: pr.PluginAfter})
		h.DismissedProfiles = slices.DeleteFunc(h.DismissedProfiles, func(x string) bool { return x == id })
		c.Hosts[host] = h
		c.Exceptions = slices.DeleteFunc(c.Exceptions, func(ex config.Exception) bool {
			return slices.ContainsFunc(pr.Removed, func(old config.Exception) bool { return old.ID == ex.ID })
		})
		c.Exceptions = append(c.Exceptions, pr.Added...)
		return nil
	})
	if errors.Is(err, errProfileUnchanged) {
		return unchanged, nil
	}
	return saved, err
}
func (s *Service) RemoveProfile(host, id string, revision uint64) (config.Config, error) {
	p, ok := profiles.Get(id)
	if !ok || !config.ValidKey(host) {
		return config.Config{}, errors.New("unknown host/profile")
	}
	return s.ApplyNote(fmt.Sprintf("Removed service profile %s from %s (methods kept)", p.Name, host), func(c *config.Config) error {
		if c.Revision != revision {
			return ErrProfileConflict
		}
		h := c.Hosts[host]
		if !slices.ContainsFunc(h.Profiles, func(ap config.AppliedProfile) bool { return ap.ID == id }) {
			return errors.New("profile is not applied")
		}
		c.Exceptions = slices.DeleteFunc(c.Exceptions, func(ex config.Exception) bool { return ownsException(h, host, id, ex) })
		h.Profiles = slices.DeleteFunc(h.Profiles, func(ap config.AppliedProfile) bool { return ap.ID == id })
		c.Hosts[host] = h
		return nil
	})
}
func (s *Service) DismissProfile(host, id string, revision uint64) (config.Config, error) {
	p, ok := profiles.Get(id)
	if !ok || !config.ValidKey(host) {
		return config.Config{}, errors.New("unknown host/profile")
	}
	return s.ApplyNote(fmt.Sprintf("Dismissed service profile %s for %s", p.Name, host), func(c *config.Config) error {
		if c.Revision != revision {
			return ErrProfileConflict
		}
		h := c.Hosts[host]
		if h.Mode == "" {
			h.Mode = config.ModeInherit
		}
		if !slices.Contains(h.DismissedProfiles, id) {
			h.DismissedProfiles = append(h.DismissedProfiles, id)
		}
		c.Hosts[host] = h
		return nil
	})
}
func decorateProfiles(r *HostStatus, c config.Config, hr learning.Host, now time.Time) {
	r.SuggestedProfiles = []ProfileSuggestion{}
	r.AppliedProfiles = []ProfileState{}
	h := c.Hosts[r.Host]
	r.DismissedProfiles = append([]string{}, h.DismissedProfiles...)
	for _, ap := range h.Profiles {
		p, ok := profiles.Get(ap.ID)
		ps := ProfileState{AppliedProfile: ap, Name: ap.ID, Modified: !ok}
		if ok {
			ps.Name = p.Name
			ps.Inactive = p.CRSPlugin != "" && (c.Engine != config.EngineCoraza || ap.PluginCommit != crsplugins.Commit(p.CRSPlugin))
			ps.UpdateAvailable = p.Version > ap.Version || p.CRSPlugin != "" && ap.PluginCommit != crsplugins.Commit(p.CRSPlugin)
			// Only compare a catalogue at the same version. Old versions are retained
			// until the admin reviews the replacement, never silently re-materialised.
			if ap.Version == p.Version {
				ps.Modified = profileModified(c, r.Host, ap, p, now)
			}
		}
		r.AppliedProfiles = append(r.AppliedProfiles, ps)
	}
	if !r.Protected || r.Disabled || r.Wildcard {
		return
	}
	for _, p := range profiles.All() {
		if p.CRSPlugin != "" && c.Engine != config.EngineCoraza || slices.Contains(h.DismissedProfiles, p.ID) || slices.ContainsFunc(h.Profiles, func(ap config.AppliedProfile) bool { return ap.ID == p.ID }) {
			continue
		}
		paths := []string{}
		used := map[string]bool{}
		for _, hint := range p.Detect.Paths {
			for path, n := range hr.Paths {
				if n >= 3 && !used[path] && (path == hint || strings.HasPrefix(path, hint) && strings.HasSuffix(hint, "/") || strings.HasPrefix(path, hint+"/")) {
					paths = append(paths, hint)
					used[path] = true
					break
				}
			}
		}
		port := 0
		for _, v := range r.UpstreamPorts {
			if slices.Contains(p.Detect.Ports, v) {
				port = v
				break
			}
		}
		if len(paths) < 2 && (len(paths) < 1 || port == 0) {
			continue
		}
		evidence := "seen " + strings.Join(paths, ", ")
		if port != 0 {
			evidence += fmt.Sprintf(", backend port %d", port)
		}
		r.SuggestedProfiles = append(r.SuggestedProfiles, ProfileSuggestion{ID: p.ID, Name: p.Name, Version: p.Version, Evidence: evidence})
	}
}

// profileModified reports whether the host's copy of a profile differs from
// the catalogue at the same version: an owned scope edited, removed, added or
// expired, or a profile method taken away again.
func profileModified(c config.Config, host string, ap config.AppliedProfile, p profiles.Profile, now time.Time) bool {
	expected := profileExceptions(host, p, now)
	actual := []config.Exception{}
	for _, ex := range c.Exceptions {
		if ex.Host == host && ex.Source == profileSource(ap.ID, ap.Version) {
			actual = append(actual, ex)
		}
	}
	if len(expected) != len(actual) {
		return true
	}
	for _, want := range expected {
		if !slices.ContainsFunc(actual, func(ex config.Exception) bool {
			return sameException(want, ex) && ex.Active(now) && ex.ExpiresAt.Sub(ex.CreatedAt) == config.MaxExceptionLife
		}) {
			return true
		}
	}
	extra, _ := p.ExtraMethods()
	for _, m := range extra {
		if !slices.Contains(c.Hosts[host].Methods, m) {
			return true
		}
	}
	return false
}
