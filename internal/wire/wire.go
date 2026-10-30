// Package wire holds the JSON types exchanged with the Zoraxy core. Field
// names and JSON keys are kept identical to the Zoraxy plugin SDK
// (mod/plugins/zoraxy_plugin) so the plugin does not depend on a vendored copy.
package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const ProtocolVersion = 1

type PluginType int

const (
	PluginTypeRouter    PluginType = 0
	PluginTypeUtilities PluginType = 1
)

type StaticCaptureRule struct {
	CapturePath string `json:"capture_path"`
}

type PermittedAPIEndpoint struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Reason   string `json:"reason"`
}

type RuntimeConstantValue struct {
	ZoraxyVersion    string `json:"zoraxy_version"`
	ZoraxyUUID       string `json:"zoraxy_uuid"`
	DevelopmentBuild bool   `json:"development_build"`
}

type IntroSpect struct {
	ID                       string                 `json:"id"`
	Name                     string                 `json:"name"`
	Author                   string                 `json:"author"`
	AuthorContact            string                 `json:"author_contact"`
	Description              string                 `json:"description"`
	URL                      string                 `json:"url"`
	Type                     PluginType             `json:"type"`
	VersionMajor             int                    `json:"version_major"`
	VersionMinor             int                    `json:"version_minor"`
	VersionPatch             int                    `json:"version_patch"`
	StaticCapturePaths       []StaticCaptureRule    `json:"static_capture_paths"`
	StaticCaptureIngress     string                 `json:"static_capture_ingress"`
	DynamicCaptureSniff      string                 `json:"dynamic_capture_sniff"`
	DynamicCaptureIngress    string                 `json:"dynamic_capture_ingress"`
	RequestInspect           string                 `json:"request_inspect,omitempty"`
	RequestInspectMaxBody    int                    `json:"request_inspect_max_body,omitempty"`
	RequestInspectFailClosed bool                   `json:"request_inspect_fail_closed,omitempty"`
	RequestInspectPolicy     string                 `json:"request_inspect_policy,omitempty"`
	UIPath                   string                 `json:"ui_path"`
	DashboardWidget          string                 `json:"dashboard_widget,omitempty"`
	SubscriptionPath         string                 `json:"subscription_path"`
	SubscriptionsEvents      map[string]string      `json:"subscriptions_events"`
	PermittedAPIEndpoints    []PermittedAPIEndpoint `json:"permitted_api_endpoints"`
}

type ConfigureSpec struct {
	Port         int                  `json:"port"`
	RuntimeConst RuntimeConstantValue `json:"runtime_const"`
	APIKey       string               `json:"api_key,omitempty"`
	ZoraxyPort   int                  `json:"zoraxy_port,omitempty"`
}

// SniffRequest mirrors zoraxy_plugin.DynamicSniffForwardRequest.
type SniffRequest struct {
	Method     string              `json:"method"`
	Hostname   string              `json:"hostname"`
	URL        string              `json:"url"`
	Header     map[string][]string `json:"header"`
	RemoteAddr string              `json:"remote_addr"`
	ClientIP   string              `json:"client_ip"`
	Host       string              `json:"host"`
	RequestURI string              `json:"request_uri"`
	Proto      string              `json:"proto"`
	ProtoMajor int                 `json:"proto_major"`
	ProtoMinor int                 `json:"proto_minor"`
}

// InspectPayload is the flat sniff metadata plus the bounded body prefix.
type InspectPayload struct {
	SniffRequest
	Body            []byte `json:"body"`
	BodyTruncated   bool   `json:"body_truncated"`
	ProtocolVersion int    `json:"protocol_version,omitempty"`
	RouteID         string `json:"route_id,omitempty"`
}

type InspectResult struct {
	Action  string `json:"action"`
	Status  int    `json:"status,omitempty"`
	Reason  string `json:"reason,omitempty"`
	EventID string `json:"event_id,omitempty"`
}

type HostPolicy struct {
	Mode          string `json:"mode"`
	MaxBodyKB     int    `json:"max_body_kb,omitempty"`
	BodyTimeoutMS int    `json:"body_timeout_ms,omitempty"`
}

// Policy is the control-plane snapshot served on RequestInspectPolicy.
type Policy struct {
	Mode               string                `json:"mode"`
	FailClosed         bool                  `json:"fail_closed"`
	InvertFailureHosts []string              `json:"invert_failure_hosts"`
	MaxBodyKB          int                   `json:"max_body_kb"`
	BodyTimeoutMS      int                   `json:"body_timeout_ms"`
	Hosts              map[string]HostPolicy `json:"hosts"`
}

// Normalized returns a copy whose list/map fields encode as [] and {} rather
// than null, matching the documented control-plane JSON.
func (p Policy) Normalized() Policy {
	if p.InvertFailureHosts == nil {
		p.InvertFailureHosts = []string{}
	}
	if p.Hosts == nil {
		p.Hosts = map[string]HostPolicy{}
	}
	return p
}

// DecodeInspectPayload decodes one inspection request. Unknown fields are
// ignored so the core can add metadata without breaking older plugins, but
// trailing data, unsupported protocol versions and malformed requests fail.
func DecodeInspectPayload(r io.Reader, max int64) (InspectPayload, error) {
	var p InspectPayload
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return p, fmt.Errorf("read payload: %w", err)
	}
	if int64(len(data)) > max {
		return p, errors.New("payload exceeds size limit")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&p); err != nil {
		return InspectPayload{}, fmt.Errorf("decode payload: %w", err)
	}
	if dec.More() {
		return InspectPayload{}, errors.New("trailing data after payload")
	}
	if _, err := dec.Token(); err != io.EOF {
		return InspectPayload{}, errors.New("trailing data after payload")
	}
	if p.ProtocolVersion < 0 || p.ProtocolVersion > ProtocolVersion {
		return InspectPayload{}, fmt.Errorf("unsupported protocol_version %d", p.ProtocolVersion)
	}
	if !isToken(p.Method) {
		return InspectPayload{}, errors.New("invalid method")
	}
	if p.RequestURI == "" || len(p.RequestURI) > 64*1024 {
		return InspectPayload{}, errors.New("invalid request_uri")
	}
	return p, nil
}

// isToken reports whether s is a non-empty RFC 9110 token.
func isToken(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if c > 0x7e || c <= 0x20 || strings.ContainsRune(`"(),/:;<=>?@[\]{}`, c) {
			return false
		}
	}
	return true
}

// ParseConfigureArgs reads the -configure payload Zoraxy passes on start,
// accepting both "-configure=<json>" and "-configure <json>".
func ParseConfigureArgs(args []string) (*ConfigureSpec, error) {
	var raw string
	found := false
	for i, a := range args {
		if strings.HasPrefix(a, "-configure=") {
			raw, found = strings.TrimPrefix(a, "-configure="), true
			break
		}
		if a == "-configure" {
			if i+1 >= len(args) {
				return nil, errors.New("missing value after -configure")
			}
			raw, found = args[i+1], true
			break
		}
	}
	if !found {
		return nil, errors.New("no -configure flag found")
	}
	var spec ConfigureSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		return nil, fmt.Errorf("parse -configure: %w", err)
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d", spec.Port)
	}
	return &spec, nil
}
