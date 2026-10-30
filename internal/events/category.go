package events

// Attack categories derived from OWASP CRS rule-ID families. Shown in the
// overview donut and event list; "Other" for engines without CRS IDs.
var crsFamilies = []struct {
	from, to int
	name     string
}{
	{913000, 914000, "Scanner / bot"},
	{920000, 921000, "Protocol violation"},
	{921000, 922000, "Protocol attack"},
	{922000, 923000, "Multipart abuse"},
	{930000, 931000, "File inclusion (LFI)"},
	{931000, 932000, "Remote file inclusion"},
	{932000, 933000, "Command injection (RCE)"},
	{933000, 934000, "PHP injection"},
	{934000, 935000, "Generic attack / SSRF"},
	{941000, 942000, "Cross-site scripting (XSS)"},
	{942000, 943000, "SQL injection"},
	{943000, 944000, "Session fixation"},
	{944000, 945000, "Java attack"},
}

// Category names a CRS rule family in plain words; "" for non-detection rules.
func Category(ruleID int) string {
	if nonDetection(ruleID) {
		return ""
	}
	for _, f := range crsFamilies {
		if ruleID >= f.from && ruleID < f.to {
			return f.name
		}
	}
	if ruleID > 0 {
		return "Other rule"
	}
	return ""
}

// Category of an event: the first detection rule's family, else what happened.
func (ev Event) Category() string {
	switch ev.Action {
	case ActionError:
		return "Inspection error"
	case ActionOversize:
		return "Body too large"
	}
	for _, m := range ev.Matches {
		if c := Category(m.RuleID); c != "" {
			return c
		}
	}
	if len(ev.Matches) > 0 {
		return "Engine rule"
	}
	return "Unknown"
}
