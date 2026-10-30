package events

import (
	"testing"

	"zoraxy-waf-plugin/internal/engine"
)

func TestCategory(t *testing.T) {
	for id, want := range map[int]string{942100: "SQL injection", 941100: "Cross-site scripting (XSS)", 932130: "Command injection (RCE)",
		930120: "File inclusion (LFI)", 913100: "Scanner / bot", 920350: "Protocol violation", 949110: "", 980130: "", 0: "", 12345: "Other rule"} {
		if got := Category(id); got != want {
			t.Errorf("Category(%d) = %q, want %q", id, got, want)
		}
	}
	ev := Event{Action: ActionBlocked, Matches: []engine.Match{{RuleID: 949110}, {RuleID: 942100}, {RuleID: 941100}}}
	if got := ev.Category(); got != "SQL injection" {
		t.Fatalf("first detection rule wins, got %q", got)
	}
	if got := (Event{Action: ActionError}).Category(); got != "Inspection error" {
		t.Fatal(got)
	}
	if got := (Event{Action: ActionWouldBlock, Matches: []engine.Match{{RuleID: 0, Message: "crowdsec"}}}).Category(); got != "Engine rule" {
		t.Fatal(got)
	}
	if got := (Event{Action: ActionWouldBlock}).Category(); got != "Unknown" {
		t.Fatal(got)
	}
}
