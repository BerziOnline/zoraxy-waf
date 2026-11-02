// Package zoraxy reads the HTTP proxy routes of the Zoraxy instance that runs
// the plugin, through the plugin API (permitted endpoints in IntroSpect).
// Read-only: the WAF never changes Zoraxy's configuration.
package zoraxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Endpoints the plugin asks Zoraxy for (declared in IntroSpect).
const (
	EndpointProxyList    = "/plugin/api/proxy/list"
	EndpointPluginGroups = "/plugin/api/plugins/groups/list"
	maxResponse          = 8 << 20
)

// Route is one HTTP proxy rule as the WAF needs it.
type Route struct {
	Host     string   `json:"host"`              // matching domain (route key)
	Aliases  []string `json:"aliases,omitempty"` // alias domains of the rule
	Tags     []string `json:"tags,omitempty"`
	Disabled bool     `json:"disabled"`
	// Protected: one of the route's tags sends its traffic through this
	// plugin (Zoraxy plugin groups). Untagged routes are never inspected.
	Protected     bool  `json:"protected"`
	UpstreamPorts []int `json:"upstream_ports,omitempty"`
}

// Client calls the Zoraxy plugin API of the local Zoraxy with the plugin's
// API key.
type Client struct {
	// BaseURL is the address that answered last; Candidates are tried in
	// order when it does not answer.
	BaseURL    string
	Candidates []string
	APIKey     string
	PluginID   string
	HTTP       *http.Client
	mu         sync.Mutex
}

// New returns a client for the Zoraxy web UI port handed over at plugin
// start, or nil when Zoraxy gave no API key (older Zoraxy, no permission).
// Zoraxy passes only the port, and its web UI may listen on one LAN address
// instead of loopback (-port=10.0.0.5:8000), so the client tries loopback
// first and then the addresses of this machine. Traffic never leaves it.
func New(port int, apiKey, pluginID string) *Client {
	if port <= 0 || apiKey == "" {
		return nil
	}
	p := strconv.Itoa(port)
	cands := []string{"http://127.0.0.1:" + p, "http://[::1]:" + p}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		var v4, v6 []string
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			if ipn.IP.To4() != nil {
				v4 = append(v4, "http://"+net.JoinHostPort(ipn.IP.String(), p))
			} else {
				v6 = append(v6, "http://"+net.JoinHostPort(ipn.IP.String(), p))
			}
		}
		cands = append(append(cands, v4...), v6...)
	}
	dial := &net.Dialer{Timeout: time.Second}
	return &Client{BaseURL: cands[0], Candidates: cands, APIKey: apiKey, PluginID: pluginID,
		HTTP: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: dial.DialContext, MaxIdleConns: 2, IdleConnTimeout: time.Minute}}}
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	c.mu.Lock()
	order := []string{c.BaseURL}
	for _, b := range c.Candidates {
		if b != c.BaseURL {
			order = append(order, b)
		}
	}
	c.mu.Unlock()
	// A candidate counts only with a valid answer (200 + expected JSON): an
	// unrelated service on the same port must not hide Zoraxy on another
	// address of this machine.
	var lastErr error
	for _, base := range order {
		err := c.try(ctx, base+path, path, out)
		if err == nil {
			c.mu.Lock()
			c.BaseURL = base
			c.mu.Unlock()
			return nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if errors.Is(lastErr, errUnreachable) {
		return fmt.Errorf("Zoraxy API not reachable on port %s of this machine", portOf(order[0]))
	}
	return lastErr
}

var errUnreachable = errors.New("unreachable")

func (c *Client) try(ctx context.Context, url, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return errUnreachable
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return errors.New("Zoraxy API answer unreadable")
	}
	if len(body) > maxResponse {
		return errors.New("Zoraxy API answer too large")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Zoraxy API answered %d for %s (permission missing?)", resp.StatusCode, path)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("Zoraxy API answer for %s not understood", path)
	}
	return nil
}

// Routes lists the host routes with their plugin protection.
func (c *Client) Routes(ctx context.Context) ([]Route, []string, error) {
	var raw []struct {
		RootOrMatchingDomain string
		MatchingDomainAlias  []string
		Tags                 []string
		Disabled             bool
		ActiveOrigins        []struct{ OriginIpOrDomain string }
	}
	if err := c.get(ctx, EndpointProxyList+"?type=host", &raw); err != nil {
		return nil, nil, err
	}
	var groups map[string][]string
	if err := c.get(ctx, EndpointPluginGroups, &groups); err != nil {
		return nil, nil, err
	}
	mine := map[string]bool{}
	for tag, ids := range groups {
		for _, id := range ids {
			if id == c.PluginID {
				mine[tag] = true
			}
		}
	}
	tags := make([]string, 0, len(mine))
	for t := range mine {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	out := make([]Route, 0, len(raw))
	for _, r := range raw {
		host := strings.ToLower(strings.TrimSpace(r.RootOrMatchingDomain))
		if host == "" {
			continue
		}
		rt := Route{Host: host, Tags: append([]string{}, r.Tags...), Disabled: r.Disabled}
		ports := map[int]bool{}
		for _, origin := range r.ActiveOrigins {
			if _, p, err := net.SplitHostPort(origin.OriginIpOrDomain); err == nil {
				if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
					ports[n] = true
				}
			}
		}
		for p := range ports {
			rt.UpstreamPorts = append(rt.UpstreamPorts, p)
		}
		sort.Ints(rt.UpstreamPorts)
		for _, a := range r.MatchingDomainAlias {
			if a = strings.ToLower(strings.TrimSpace(a)); a != "" && a != host {
				rt.Aliases = append(rt.Aliases, a)
			}
		}
		for _, t := range r.Tags {
			if mine[t] {
				rt.Protected = true
			}
		}
		out = append(out, rt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, tags, nil
}

func portOf(base string) string {
	if i := strings.LastIndex(base, ":"); i >= 0 {
		return base[i+1:]
	}
	return "?"
}
