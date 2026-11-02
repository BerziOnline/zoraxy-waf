package config

import (
	"testing"
	"time"
)

func TestProfileMetadataValidationAndClone(t *testing.T) {
	c := Default()
	c.Hosts["chat.example.test"] = HostOverride{Mode: ModeInherit, Profiles: []AppliedProfile{{ID: "mattermost", Version: 1, ExceptionIDs: []string{"one"}}}, DismissedProfiles: []string{"immich"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	d := c.Clone()
	h := d.Hosts["chat.example.test"]
	h.Profiles[0].ExceptionIDs[0] = "changed"
	h.DismissedProfiles[0] = "changed"
	if c.Hosts["chat.example.test"].Profiles[0].ExceptionIDs[0] != "one" || c.Hosts["chat.example.test"].DismissedProfiles[0] != "immich" {
		t.Fatal("clone aliases profile metadata")
	}
	for _, p := range []AppliedProfile{{ID: "../bad", Version: 1}, {ID: "mattermost", Version: 0}, {ID: "mattermost", Version: 1, PluginCommit: "not-a-commit"}} {
		h := c.Hosts["chat.example.test"]
		h.Profiles = []AppliedProfile{p}
		d = c.Clone()
		d.Hosts["chat.example.test"] = h
		if d.Validate() == nil {
			t.Fatal("invalid profile accepted", p)
		}
	}
}

func TestProfileExceptionMatchesExactHostOnly(t *testing.T) {
	now := time.Now()
	ex := Exception{RuleID: 932125, Host: "chat.example.test", Method: "POST", Path: "/api/v4/posts", Argument: "json.message", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if !ex.Matches("alias.example.test", "chat.example.test", "POST", "/api/v4/posts", now) {
		t.Fatal("manual exception must keep route scope")
	}
	ex.Source = "profile:mattermost@1"
	if ex.Matches("alias.example.test", "chat.example.test", "POST", "/api/v4/posts", now) {
		t.Fatal("profile exception leaked to a route alias")
	}
	if !ex.Matches("CHAT.example.test:443", "", "POST", "/api/v4/posts", now) {
		t.Fatal("profile exception must match its own host")
	}
}
