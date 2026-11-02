// Package crsplugins embeds unmodified, pinned official CRS exclusion plugins.
package crsplugins

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

//go:embed manifest.json vendor/*/LICENSE vendor/*/plugins/*.conf
var files embed.FS

type Plugin struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Version    string `json:"version"`
	Shipped    bool   `json:"shipped"`
	SkipReason string `json:"skip_reason,omitempty"`
	Range      struct {
		Start int `json:"start"`
		End   int `json:"end"`
	} `json:"rule_id_range"`
}

func Manifest() []Plugin {
	b, _ := files.ReadFile("manifest.json")
	var m struct {
		Plugins []Plugin `json:"plugins"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		panic(err)
	}
	return m.Plugins
}
func Commit(name string) string {
	for _, p := range Manifest() {
		if p.Name == name && p.Shipped {
			return p.Commit
		}
	}
	return ""
}
func Known(name string) bool {
	for _, p := range Manifest() {
		if p.Name == name && p.Shipped {
			return true
		}
	}
	return false
}

// Directives returns the documented config -> before -> CRS -> after order.
// gates remove the entire assigned plugin ID block *before* its first rule,
// even rules preceding its own enabled-variable guard. SERVER_NAME is set
// by Coraza's caller to the canonical request host, never a client header.
func Directives(hosts map[string][]string) (string, string, error) {
	var config, gates, before, after strings.Builder
	for i, p := range Manifest() {
		enabled := append([]string{}, hosts[p.Name]...)
		if len(enabled) == 0 {
			continue
		}
		if !p.Shipped {
			return "", "", fmt.Errorf("plugin %s is not shipped", p.Name)
		}
		sort.Strings(enabled)
		escaped := []string{}
		for _, host := range enabled {
			escaped = append(escaped, regexp.QuoteMeta(host))
		}
		// An exact anchored alternation, never @within / substring matching.
		fmt.Fprintf(&gates, "SecRule SERVER_NAME \"!@rx ^(?:%s)$\" \"id:%d,phase:1,pass,t:none,nolog,ctl:ruleRemoveById=%d-%d\"\n", strings.Join(escaped, "|"), 110000+i, p.Range.Start, p.Range.End)
		for _, part := range []struct {
			suffix string
			out    *strings.Builder
		}{{"config", &config}, {"before", &before}, {"after", &after}} {
			paths, err := fs.Glob(files, "vendor/"+p.Name+"/plugins/*-"+part.suffix+".conf")
			if err != nil {
				return "", "", err
			}
			for _, path := range paths {
				b, err := files.ReadFile(path)
				if err != nil {
					return "", "", err
				}
				part.out.Write(b)
				part.out.WriteByte('\n')
			}
		}
	}
	// Some upstream packages allow TRACE for WebDAV; this reverse proxy never
	// permits reflection or tunnels, even when an app package enables them.
	if gates.Len() > 0 {
		gates.WriteString("SecRule REQUEST_METHOD \"@rx ^(?:TRACE|CONNECT)$\" \"id:110099,phase:1,deny,status:403,t:none,log,msg:'Unsafe proxy method'\"\n")
	}
	return config.String() + gates.String() + before.String(), after.String(), nil
}
