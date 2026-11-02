// Package profiles validates the curated catalogue before it can affect policy.
package profiles

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"zoraxy-waf-plugin/internal/crsplugins"
	data "zoraxy-waf-plugin/profiles"
)

type Detect struct {
	Paths []string `json:"paths"`
	Ports []int    `json:"upstream_ports,omitempty"`
}
type Exception struct {
	Rules             []int             `json:"rules"`
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	Argument          string            `json:"argument"`
	Reason            string            `json:"reason"`
	TargetClass       string            `json:"target_class"`
	AcceptedBlindSpot map[string]string `json:"accepted_blind_spot,omitempty"`
}

// ClassFamilies maps each attack class of the profile security gate to its
// OWASP CRS rule id range.
var ClassFamilies = map[string][2]int{
	"protocol":  {920000, 920999},
	"traversal": {930000, 930999},
	"rfi":       {931000, 931999},
	"command":   {932000, 932999},
	"php":       {933000, 933999},
	"xss":       {941000, 941999},
	"sqli":      {942000, 942999},
}

type Profile struct {
	SchemaVersion int             `json:"schema_version"`
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Version       int             `json:"version"`
	Homepage      string          `json:"homepage"`
	Detect        Detect          `json:"detect"`
	Methods       json.RawMessage `json:"methods"`
	Exceptions    []Exception     `json:"exceptions"`
	CRSPlugin     string          `json:"crs_plugin,omitempty"`
}

var idRX = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
var argumentRX = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,255}$`)
var methodRX = regexp.MustCompile(`^[A-Z][A-Z-]{2,15}$`)

func ValidID(id string) bool { return idRX.MatchString(id) }
func ValidPath(p string) bool {
	return strings.HasPrefix(p, "/") && p != "/" && p != "/*" && len(p) <= 1024 && !strings.ContainsAny(p, " ?#\r\n\t") && !strings.Contains(strings.TrimSuffix(p, "*"), "*")
}

// ExtraMethods returns only methods outside the always-allowed CRS defaults.
func (p Profile) ExtraMethods() ([]string, error) {
	var preset string
	var list []string
	if err := json.Unmarshal(p.Methods, &preset); err == nil {
		switch preset {
		case "website":
			return []string{}, nil
		case "app":
			return []string{"PUT", "PATCH", "DELETE"}, nil
		default:
			return nil, fmt.Errorf("unknown methods preset")
		}
	}
	if err := json.Unmarshal(p.Methods, &list); err != nil || list == nil {
		return nil, fmt.Errorf("methods must be a preset or list")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, m := range list {
		if !methodRX.MatchString(m) || m == "TRACE" || m == "CONNECT" || seen[m] {
			return nil, fmt.Errorf("invalid method %q", m)
		}
		seen[m] = true
		switch m {
		case "GET", "HEAD", "POST", "OPTIONS":
		default:
			out = append(out, m)
		}
	}
	if len(out) > 16 {
		return nil, fmt.Errorf("too many methods")
	}
	return out, nil
}

var ruleOnce sync.Once
var ruleIDs map[int]bool
var ruleErr error

// RuleIDs reads the actual pinned embedded CRS, not an assumed numeric range.
func RuleIDs() (map[int]bool, error) {
	ruleOnce.Do(func() {
		ruleIDs = map[int]bool{}
		rx := regexp.MustCompile(`\bid\s*:\s*['"]?(\d+)`)
		ruleErr = fs.WalkDir(crs.FS, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".conf") {
				return nil
			}
			b, err := fs.ReadFile(crs.FS, path)
			if err != nil {
				return err
			}
			// Commented example rules are not real rules.
			lines := strings.Split(string(b), "\n")
			var active strings.Builder
			for _, l := range lines {
				if !strings.HasPrefix(strings.TrimSpace(l), "#") {
					active.WriteString(l)
					active.WriteByte('\n')
				}
			}
			for _, m := range rx.FindAllStringSubmatch(active.String(), -1) {
				id, _ := strconv.Atoi(m[1])
				ruleIDs[id] = true
			}
			return nil
		})
	})
	out := map[int]bool{}
	for id := range ruleIDs {
		out[id] = true
	}
	return out, ruleErr
}
func (p Profile) Validate() error {
	if p.CRSPlugin != "" && !crsplugins.Known(p.CRSPlugin) {
		return fmt.Errorf("unknown or unsafe CRS plugin %q", p.CRSPlugin)
	}
	bad := func(s string) error { return fmt.Errorf("profile %q: %s", p.ID, s) }
	if p.SchemaVersion != 1 || !ValidID(p.ID) || p.Name == "" || len(p.Name) > 80 || p.Version < 1 {
		return bad("invalid identity/version")
	}
	u, err := url.Parse(p.Homepage)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return bad("https homepage required")
	}
	if _, err := p.ExtraMethods(); err != nil {
		return bad(err.Error())
	}
	for _, path := range p.Detect.Paths {
		if !ValidPath(path) || strings.Contains(path, "*") {
			return bad("invalid detection path")
		}
	}
	for _, port := range p.Detect.Ports {
		if port < 1 || port > 65535 {
			return bad("invalid detection port")
		}
	}
	ids, err := RuleIDs()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, e := range p.Exceptions {
		if !methodRX.MatchString(e.Method) || e.Method == "TRACE" || e.Method == "CONNECT" || !ValidPath(e.Path) {
			return bad("exceptions require method, narrow path and named argument")
		}
		if e.Argument == "" {
			if !wholeRequestAllowed(e) {
				return bad("an exception without a field is only allowed for protocol rules on one exact GET or HEAD path")
			}
		} else if !argumentRX.MatchString(e.Argument) {
			return bad("exceptions require method, narrow path and named argument")
		}
		if len(e.Rules) == 0 || len(e.Reason) < 10 || len(e.Reason) > 350 || strings.ContainsAny(e.Reason, "\r\n") || !strings.HasSuffix(e.Reason, ".") || strings.Contains(strings.TrimSuffix(e.Reason, "."), ". ") || strings.ContainsAny(e.Reason, "!?") {
			return bad("rules and a plain-sentence reason required")
		}
		family, ok := ClassFamilies[e.TargetClass]
		if !ok {
			return bad("target_class required")
		}
		// Every excluded rule must belong to the attack class the profile
		// names, so a rule cannot hide under a class whose tests it skips.
		for _, id := range e.Rules {
			if id < family[0] || id > family[1] {
				return bad(fmt.Sprintf("rule %d is not in the %s family", id, e.TargetClass))
			}
		}
		for c, reason := range e.AcceptedBlindSpot {
			if _, ok := ClassFamilies[c]; !ok || len(strings.TrimSpace(reason)) < 10 {
				return bad("invalid accepted blind spot")
			}
		}
		for _, id := range e.Rules {
			if !ids[id] || id == 911100 || id/1000 == 949 || id/1000 == 959 || id/1000 == 980 {
				return bad(fmt.Sprintf("unsafe or unknown rule %d", id))
			}
			k := fmt.Sprintf("%d|%s|%s|%s", id, e.Method, e.Path, e.Argument)
			if seen[k] {
				return bad("duplicate exception")
			}
			seen[k] = true
		}
	}
	return nil
}
func Load(fsys fs.FS) ([]Profile, error) {
	files, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, err
	}
	out := []Profile{}
	seen := map[string]bool{}
	for _, file := range files {
		b, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, err
		}
		var p Profile
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if dec.Decode(new(any)) != io.EOF {
			return nil, fmt.Errorf("%s: trailing JSON", file)
		}
		if err := p.Validate(); err != nil {
			return nil, err
		}
		if seen[p.ID] {
			return nil, fmt.Errorf("duplicate profile %s", p.ID)
		}
		seen[p.ID] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var catalogue = func() []Profile {
	p, err := Load(data.FS)
	if err != nil {
		panic(err)
	}
	return p
}()

// All and Get return detached values: callers cannot mutate the embedded catalogue.
func All() []Profile {
	b, _ := json.Marshal(catalogue)
	var p []Profile
	_ = json.Unmarshal(b, &p)
	return p
}
func Get(id string) (Profile, bool) {
	for _, p := range All() {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}

// wholeRequestAllowed limits profile exceptions without a named field to
// protocol rules (920xxx, e.g. the content-type policy) on one exact path of a
// request without a body: such rules look at a header, not at user input.
func wholeRequestAllowed(e Exception) bool {
	return e.Argument == "" && e.TargetClass == "protocol" && !strings.Contains(e.Path, "*") && (e.Method == "GET" || e.Method == "HEAD")
}
