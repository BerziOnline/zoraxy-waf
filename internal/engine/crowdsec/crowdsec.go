// Package crowdsec forwards requests to a CrowdSec AppSec component using
// its documented remediation-component protocol
// (https://docs.crowdsec.net/docs/appsec/protocol/):
//
//   - GET when the original request has no body, POST with the body otherwise
//   - trusted X-Crowdsec-Appsec-{Ip,Uri,Host,Verb,Api-Key,User-Agent,Http-Version}
//     headers, overriding anything the client sent under that prefix
//   - 200 {"action":"allow"}; 403 {"action":"ban","http_status":N}
//   - 401, 500, captcha/challenge and anything unexpected are adapter errors
//
// The adapter has been tested against a local mock of that contract only.
package crowdsec

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"zoraxy-waf-plugin/internal/config"
	"zoraxy-waf-plugin/internal/engine"
)

const maxResponse = 4096

type Config struct {
	URL     string
	APIKey  string
	Timeout time.Duration
	RootCAs *x509.CertPool // nil: system roots
}

type Engine struct {
	url    string
	host   string
	key    string
	client *http.Client

	mu        sync.Mutex
	lastErr   string
	lastErrAt time.Time
	lastOKAt  time.Time
	failing   bool
}

func New(c Config) (*Engine, error) {
	if err := config.ValidateCrowdSecURL(c.URL); err != nil {
		return nil, fmt.Errorf("crowdsec url: %w", err)
	}
	if c.APIKey == "" {
		return nil, errors.New("crowdsec api key required")
	}
	if c.Timeout <= 0 {
		return nil, errors.New("crowdsec timeout required")
	}
	u, _ := url.Parse(c.URL)
	tr := &http.Transport{
		Proxy:                 nil, // never use HTTP(S)_PROXY from the environment
		DialContext:           (&net.Dialer{Timeout: c.Timeout}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.RootCAs},
		TLSHandshakeTimeout:   c.Timeout,
		ResponseHeaderTimeout: c.Timeout,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       64,
		IdleConnTimeout:       60 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	return &Engine{
		url:  c.URL,
		host: u.Host,
		key:  c.APIKey,
		client: &http.Client{
			Transport:     tr,
			Timeout:       c.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (e *Engine) Capabilities() engine.Capabilities {
	return engine.Capabilities{Name: "crowdsec", RequestBody: true}
}

func (e *Engine) Health() engine.Health {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := engine.Health{OK: !e.failing, RuleSet: "managed by CrowdSec (remote)"}
	switch {
	case e.failing:
		h.Detail = fmt.Sprintf("AppSec %s failing since %s: %s", e.host, e.lastErrAt.UTC().Format(time.RFC3339), e.lastErr)
	case !e.lastOKAt.IsZero():
		h.Detail = fmt.Sprintf("AppSec %s reachable, last success %s", e.host, e.lastOKAt.UTC().Format(time.RFC3339))
	default:
		h.Detail = fmt.Sprintf("AppSec %s configured, not contacted yet", e.host)
	}
	return h
}

func (e *Engine) Close() error {
	e.client.CloseIdleConnections()
	return nil
}

func (e *Engine) record(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		e.failing, e.lastErr, e.lastErrAt = true, err.Error(), time.Now()
		return
	}
	e.failing, e.lastOKAt = false, time.Now()
}

var hopHeaders = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
	"Host": true, "Content-Length": true,
}

func (e *Engine) Inspect(ctx context.Context, r *engine.Request, o engine.Options) (engine.Decision, error) {
	if err := ctx.Err(); err != nil {
		return engine.Decision{}, err
	}
	if len(o.Exclusions) > 0 {
		return engine.Decision{}, fmt.Errorf("rule exclusions: %w (manage exclusions in CrowdSec)", engine.ErrUnsupported)
	}
	d, err := e.do(ctx, r)
	if err != nil && ctx.Err() == nil {
		e.record(err)
	} else if err == nil {
		e.record(nil)
	}
	return d, err
}

func (e *Engine) do(ctx context.Context, r *engine.Request) (engine.Decision, error) {
	method, body := http.MethodGet, io.Reader(nil)
	if len(r.Body) > 0 {
		method, body = http.MethodPost, bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.url, body)
	if err != nil {
		return engine.Decision{}, errors.New("build AppSec request failed")
	}
	for k, vs := range r.Header {
		ck := http.CanonicalHeaderKey(k)
		if hopHeaders[ck] || strings.HasPrefix(ck, "X-Crowdsec-Appsec-") {
			continue
		}
		for _, v := range vs {
			req.Header.Add(ck, v)
		}
	}
	ua := ""
	if v := r.Header["User-Agent"]; len(v) > 0 {
		ua = v[0]
	}
	req.Header.Set("X-Crowdsec-Appsec-Ip", r.ClientIP)
	req.Header.Set("X-Crowdsec-Appsec-Uri", r.RawURI)
	req.Header.Set("X-Crowdsec-Appsec-Host", r.Host)
	req.Header.Set("X-Crowdsec-Appsec-Verb", r.Method)
	req.Header.Set("X-Crowdsec-Appsec-Api-Key", e.key)
	req.Header.Set("X-Crowdsec-Appsec-User-Agent", ua)
	req.Header.Set("X-Crowdsec-Appsec-Http-Version", httpVersion(r.Proto))

	resp, err := e.client.Do(req)
	if err != nil {
		// url.Error includes only the configured URL (no credentials).
		var ue *url.Error
		if errors.As(err, &ue) {
			return engine.Decision{}, fmt.Errorf("AppSec request failed: %v", ue.Err)
		}
		return engine.Decision{}, fmt.Errorf("AppSec request failed: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return engine.Decision{}, fmt.Errorf("AppSec response read failed: %v", err)
	}
	if len(data) > maxResponse {
		return engine.Decision{}, errors.New("AppSec response exceeds 4096 bytes")
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusForbidden:
	case http.StatusUnauthorized:
		return engine.Decision{}, errors.New("AppSec rejected the API key (401)")
	default:
		return engine.Decision{}, fmt.Errorf("AppSec returned unexpected status %d", resp.StatusCode)
	}
	var body2 struct {
		Action     string `json:"action"`
		HTTPStatus int    `json:"http_status"`
	}
	if err := json.Unmarshal(data, &body2); err != nil {
		return engine.Decision{}, fmt.Errorf("AppSec returned invalid JSON (status %d)", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusOK {
		if body2.Action != "allow" {
			return engine.Decision{}, fmt.Errorf("AppSec status 200 with unexpected action %q", truncate(body2.Action))
		}
		return engine.Decision{Action: "allow"}, nil
	}
	switch body2.Action {
	case "ban":
		st := body2.HTTPStatus
		if st < 400 || st > 599 {
			st = http.StatusForbidden
		}
		return engine.Decision{Interrupted: true, Status: st, Action: "ban"}, nil
	case "captcha", "challenge":
		return engine.Decision{}, fmt.Errorf("AppSec action %q: %w", body2.Action, engine.ErrChallenge)
	default:
		return engine.Decision{}, fmt.Errorf("AppSec status 403 with unexpected action %q", truncate(body2.Action))
	}
}

func truncate(s string) string {
	if len(s) > 32 {
		return s[:32]
	}
	return s
}

// httpVersion renders "HTTP/1.1" as "11", "HTTP/2.0" as "20".
func httpVersion(proto string) string {
	var major, minor int
	if _, err := fmt.Sscanf(proto, "HTTP/%d.%d", &major, &minor); err != nil {
		if _, err := fmt.Sscanf(proto, "HTTP/%d", &major); err != nil {
			return "11"
		}
	}
	return strconv.Itoa(major*10 + minor)
}
