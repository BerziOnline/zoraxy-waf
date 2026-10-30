// Package engine defines the adapter contract between the plugin runtime and
// an inspection engine (in-process Coraza, remote CrowdSec AppSec, ...).
package engine

import (
	"context"
	"errors"
)

// Request is one HTTP request as seen by Zoraxy before routing.
type Request struct {
	ID            string
	Method        string
	RawURI        string
	Proto         string
	Host          string
	RouteID       string
	ClientIP      string
	Header        map[string][]string
	Body          []byte
	BodyTruncated bool
}

// Exclusion removes one rule, or one rule for one argument, from a single
// transaction before evaluation.
type Exclusion struct {
	RuleID   int
	Argument string // empty: remove the whole rule
}

type Options struct {
	ParanoiaLevel int
	Exclusions    []Exclusion
}

// Match is a redaction-safe description of a matched rule: no matched values.
type Match struct {
	RuleID   int      `json:"rule_id"`
	Message  string   `json:"message"`
	Severity string   `json:"severity,omitempty"`
	Phase    int      `json:"phase,omitempty"`
	Targets  []string `json:"targets,omitempty"` // e.g. ARGS_GET:q
	Tags     []string `json:"tags,omitempty"`
}

// Decision is the engine's evaluation. Interrupted means the engine would
// block; the runtime decides whether to enforce it based on the mode.
type Decision struct {
	Interrupted  bool
	Status       int
	Action       string // engine action, e.g. deny / ban
	Matches      []Match
	AnomalyScore int
	// RuleDetails is false when the engine cannot report which rules
	// matched (CrowdSec AppSec response protocol).
	RuleDetails bool
}

type Capabilities struct {
	Name           string `json:"name"`
	RequestBody    bool   `json:"request_body"`
	RuleExclusions bool   `json:"rule_exclusions"`
	ParanoiaLevels bool   `json:"paranoia_levels"`
	RuleDetails    bool   `json:"rule_details"`
	Challenge      bool   `json:"challenge"`
	ResponsePhases bool   `json:"response_phases"`
}

type Health struct {
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`
	RuleSet string `json:"rule_set,omitempty"`
	Rules   int    `json:"rules,omitempty"`
}

// Engine implementations must be safe for concurrent use. Inspect runs
// synchronously in the caller's goroutine and must check ctx at entry and
// between processing steps; it must not start background work that outlives
// the call.
type Engine interface {
	Capabilities() Capabilities
	Inspect(ctx context.Context, req *Request, opts Options) (Decision, error)
	Health() Health
	Close() error
}

var (
	ErrUnsupported = errors.New("unsupported by engine")
	ErrChallenge   = errors.New("engine requested a challenge, which is not supported")
)
