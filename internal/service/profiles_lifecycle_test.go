package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/crsplugins"
	"zoraxy-waf-plugin/internal/engine"
	"zoraxy-waf-plugin/internal/profiles"
)

func TestProfilePreviewUpdateAndModifiedOwnership(t *testing.T) {
	s, _ := learningService(t, 7)
	host := "chat.example.test"
	c, err := s.ApplyProfile(host, "mattermost", true, s.Current().Revision)
	if err != nil {
		t.Fatal(err)
	}
	// An exception moved to another host leaves the profile and stays there.
	edited := c.Exceptions[0].ID
	_, err = s.Apply(func(c *config.Config) error {
		c.Exceptions[0].Host = "other.example.test"
		c.Exceptions[0].Reason = "Adjusted by the administrator."
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	st := status(t, s, host)
	if !st.AppliedProfiles[0].Modified {
		t.Fatal("edited exception must mark profile modified")
	}
	p, _ := profiles.Get("mattermost")
	p.Version = 2
	p.Exceptions = p.Exceptions[:1]
	before := s.Current()
	preview := profilePreview(before, host, p, s.opts.Now())
	// One of the profile's exceptions was moved to another host, so the update
	// replaces the remaining ones with the (shortened) first entry.
	if len(preview.Removed) != mattermostRules(t)-1 || len(preview.Added) != len(p.Exceptions[0].Rules) || preview.Unchanged {
		t.Fatal(preview)
	}
	if s.Current().Revision != before.Revision {
		t.Fatal("preview changed config")
	}
	// An unrelated exception with the same source on another host belongs there.
	_, err = s.Apply(func(c *config.Config) error {
		ex := c.Exceptions[0]
		ex.ID = "unrelated"
		ex.Host = "unrelated.example.test"
		c.Exceptions = append(c.Exceptions, ex)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	after, err := s.RemoveProfile(host, "mattermost", s.Current().Revision)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Exceptions) != 2 || after.Exceptions[0].ID != edited || after.Exceptions[1].ID != "unrelated" {
		t.Fatal("remove must keep exceptions on other hosts", after.Exceptions)
	}
}
func TestProfileSaveFailureConflictAndPersistence(t *testing.T) {
	s, _ := learningService(t, 7)
	host := "chat.example.test"
	rev := s.Current().Revision
	if _, err := s.ApplyProfile(host, "mattermost", true, rev-1); !errors.Is(err, ErrProfileConflict) {
		t.Fatal(err)
	}
	original := s.opts.Build
	s.opts.Build = func(config.Config) (engine.Engine, error) { return nil, errors.New("compile failure") }
	if _, err := s.ApplyProfile(host, "mattermost", true, rev); err == nil {
		t.Fatal("build failure accepted")
	}
	s.opts.Build = original
	if s.Current().Revision != rev || len(s.Current().Exceptions) != 0 {
		t.Fatal("failed apply published state")
	}
	// Block the atomic rename, then prove both memory and persisted policy stay old.
	path := filepath.Join(s.DataDir(), "config.json")
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ApplyProfile(host, "mattermost", true, rev); err == nil {
		t.Fatal("save failure accepted")
	}
	if s.Current().Revision != rev {
		t.Fatal("save failure published config")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	saved, err := s.ApplyProfile(host, "mattermost", true, rev)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil || loaded.Revision != saved.Revision || len(loaded.Hosts[host].Profiles[0].ExceptionIDs) != mattermostRules(t) {
		t.Fatal("applied state not durable", err)
	}
	if _, err = s.DismissProfile("other.example.test", "immich", saved.Revision); err != nil {
		t.Fatal(err)
	}
	loaded, err = config.Load(path)
	if err != nil || len(loaded.Hosts["other.example.test"].DismissedProfiles) != 1 {
		t.Fatal("dismissal not durable", err)
	}
}
func TestPinnedPluginDoesNotAutoUpdate(t *testing.T) {
	s, _ := learningService(t, 7)
	host := "cloud.example.test"
	c, err := s.ApplyProfile(host, "nextcloud", true, s.Current().Revision)
	if err != nil {
		t.Fatal(err)
	}
	pin := c.Hosts[host].Profiles[0].PluginCommit
	if pin != crsplugins.Commit("nextcloud-rule-exclusions") {
		t.Fatal("missing package pin")
	}
	// A config from a different package release cannot activate the current
	// package without review; inactive is visible and normal CRS remains on.
	_, err = s.Apply(func(c *config.Config) error {
		h := c.Hosts[host]
		h.Profiles[0].PluginCommit = strings.Repeat("a", 40)
		c.Hosts[host] = h
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	st := status(t, s, host)
	if !st.AppliedProfiles[0].Inactive || !st.AppliedProfiles[0].UpdateAvailable {
		t.Fatal(st.AppliedProfiles)
	}
	pr, err := s.PreviewProfile(host, "nextcloud")
	if err != nil || pr.Unchanged || pr.PluginBefore == pr.PluginAfter {
		t.Fatal(pr, err)
	}
	if _, err = s.ApplyProfile(host, "nextcloud", false, s.Current().Revision); err != nil {
		t.Fatal(err)
	}
	if status(t, s, host).AppliedProfiles[0].Inactive {
		t.Fatal("explicit update did not activate pin")
	}
}

// Applying a modified profile again restores the catalogue scopes; applying an
// intact one is a no-op.
func TestProfileReapplyRestoresModifiedScopes(t *testing.T) {
	s, _ := learningService(t, 7)
	host := "chat.example.test"
	if _, err := s.ApplyProfile(host, "mattermost", true, s.Current().Revision); err != nil {
		t.Fatal(err)
	}
	rev := s.Current().Revision
	if c, err := s.ApplyProfile(host, "mattermost", true, rev); err != nil || c.Revision != rev {
		t.Fatalf("intact profile re-applied: rev %d -> %d, %v", rev, c.Revision, err)
	}
	if _, err := s.Apply(func(c *config.Config) error {
		c.Exceptions = c.Exceptions[1:]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if st := status(t, s, host); !st.AppliedProfiles[0].Modified {
		t.Fatal("deleted scope must mark the profile modified")
	}
	c, err := s.ApplyProfile(host, "mattermost", true, s.Current().Revision)
	if err != nil {
		t.Fatal(err)
	}
	owned := 0
	for _, ex := range c.Exceptions {
		if ex.Host == host && ex.Source == mattermostSource(t) {
			owned++
		}
	}
	if n := mattermostRules(t); owned != n || len(c.Hosts[host].Profiles) != 1 || len(c.Hosts[host].Profiles[0].ExceptionIDs) != n {
		t.Fatalf("restore: %d owned exceptions, profiles %+v", owned, c.Hosts[host].Profiles)
	}
	if st := status(t, s, host); st.AppliedProfiles[0].Modified {
		t.Fatal("restored profile still marked modified")
	}
}
