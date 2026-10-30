// Package coraza runs OWASP CRS v4 in-process with Coraza v3.
//
// One WAF is compiled per paranoia level in use, once per configuration
// snapshot; requests never trigger rule compilation. Only request phases
// (1 and 2) and logging (5) are executed.
package coraza

import (
	"context"
	"fmt"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	corazawaf "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"

	"zoraxy-waf-plugin/internal/engine"
)

// CRSVersion is the rule set embedded by the pinned coraza-coreruleset module.
const CRSVersion = "OWASP_CRS/4.25.0"

// MaxBody is the largest body prefix accepted from the core (1 MiB).
const MaxBody = 1 << 20

// Rules that only report body-parser failures. When the core sent a
// truncated prefix, the failure is an artefact of truncation, not of the
// client, so these are excluded for that transaction (coverage is partial).
var truncationArtefactRules = []int{200002, 200003}

type Engine struct {
	wafs      map[int]corazawaf.WAF
	rules     map[int]int
	threshold int
	version   string
}

func directives(pl, threshold int) string {
	return fmt.Sprintf(`Include @coraza.conf-recommended
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit %[3]d
SecRequestBodyInMemoryLimit %[3]d
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess Off
SecAuditEngine Off
Include @crs-setup.conf.example
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%[1]d"
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%[2]d,setvar:tx.outbound_anomaly_score_threshold=4"
Include @owasp_crs/REQUEST-*.conf
`, pl, threshold, MaxBody)
}

// New compiles one WAF per requested paranoia level (1-4).
func New(levels []int, threshold int) (*Engine, error) {
	if len(levels) == 0 {
		return nil, fmt.Errorf("no paranoia level requested")
	}
	if threshold < 1 {
		return nil, fmt.Errorf("invalid anomaly threshold %d", threshold)
	}
	e := &Engine{wafs: map[int]corazawaf.WAF{}, rules: map[int]int{}, threshold: threshold, version: corazaVersion()}
	for _, pl := range levels {
		if pl < 1 || pl > 4 {
			e.Close()
			return nil, fmt.Errorf("invalid paranoia level %d", pl)
		}
		if _, ok := e.wafs[pl]; ok {
			continue
		}
		waf, err := corazawaf.NewWAF(corazawaf.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(directives(pl, threshold)))
		if err != nil {
			e.Close()
			return nil, fmt.Errorf("compile CRS PL%d: %w", pl, err)
		}
		e.wafs[pl] = waf
		if wr, ok := waf.(experimental.WAFWithRules); ok {
			e.rules[pl] = wr.RulesCount()
		}
	}
	// Exclusions depend on transaction methods that are not part of the
	// stable Coraza interface; verify once at compile time, not per request.
	for _, waf := range e.wafs {
		tx := waf.NewTransaction()
		_, ok1 := tx.(ruleRemover)
		_, ok2 := tx.(targetRemover)
		tx.Close()
		if !ok1 || !ok2 {
			e.Close()
			return nil, fmt.Errorf("coraza transaction does not support per-transaction rule removal")
		}
		break
	}
	return e, nil
}

func corazaVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/corazawaf/coraza/v3" {
				return d.Version
			}
		}
	}
	return "v3"
}

type ruleRemover interface{ RemoveRuleByID(id int) }
type targetRemover interface {
	RemoveRuleTargetByID(id int, variable variables.RuleVariable, key string, keyRx *regexp.Regexp)
}

func (e *Engine) Capabilities() engine.Capabilities {
	return engine.Capabilities{Name: "coraza", RequestBody: true, RuleExclusions: true, ParanoiaLevels: true, RuleDetails: true}
}

func (e *Engine) Health() engine.Health {
	pls := make([]int, 0, len(e.wafs))
	total := 0
	for pl := range e.wafs {
		pls = append(pls, pl)
		if e.rules[pl] > total {
			total = e.rules[pl]
		}
	}
	sort.Ints(pls)
	return engine.Health{
		OK:      len(e.wafs) > 0,
		Detail:  fmt.Sprintf("Coraza %s, compiled PL %v, anomaly threshold %d, request phases only", e.version, pls, e.threshold),
		RuleSet: CRSVersion,
		Rules:   total,
	}
}

func (e *Engine) Close() error {
	for pl, w := range e.wafs {
		if c, ok := w.(experimental.WAFCloser); ok {
			c.Close()
		}
		delete(e.wafs, pl)
	}
	return nil
}

// Inspect evaluates request phases synchronously. ctx is checked at entry
// and between processing steps; a running rule phase is not interruptible,
// so the caller bounds concurrency and request/body size.
func (e *Engine) Inspect(ctx context.Context, r *engine.Request, o engine.Options) (d engine.Decision, err error) {
	if err := ctx.Err(); err != nil {
		return d, err
	}
	waf, ok := e.wafs[o.ParanoiaLevel]
	if !ok {
		return d, fmt.Errorf("paranoia level %d is not compiled in this snapshot", o.ParanoiaLevel)
	}
	if len(r.Body) > MaxBody {
		return d, fmt.Errorf("body prefix exceeds %d bytes", MaxBody)
	}
	var tx types.Transaction
	if r.ID != "" {
		tx = waf.NewTransactionWithID(r.ID)
	} else {
		tx = waf.NewTransaction()
	}
	defer func() {
		// Logging phase and cleanup run on every exit path.
		tx.ProcessLogging()
		tx.Close()
	}()

	rr, tr := tx.(ruleRemover), tx.(targetRemover)
	for _, x := range o.Exclusions {
		if x.Argument == "" {
			rr.RemoveRuleByID(x.RuleID)
			continue
		}
		tr.RemoveRuleTargetByID(x.RuleID, variables.Args, x.Argument, nil)
		tr.RemoveRuleTargetByID(x.RuleID, variables.ArgsNames, x.Argument, nil)
	}
	if r.BodyTruncated {
		for _, id := range truncationArtefactRules {
			rr.RemoveRuleByID(id)
		}
	}

	tx.ProcessConnection(r.ClientIP, 0, "", 0)
	proto := r.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	tx.ProcessURI(r.RawURI, r.Method, proto)
	host := r.Host
	if h, _, ok := strings.Cut(host, ":"); ok && !strings.HasPrefix(host, "[") {
		host = h
	}
	tx.SetServerName(host)
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
	}
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		if !strings.EqualFold(k, "Host") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i%32 == 31 {
			if err := ctx.Err(); err != nil {
				return d, err
			}
		}
		for _, v := range r.Header[k] {
			tx.AddRequestHeader(k, v)
		}
	}
	if err := ctx.Err(); err != nil {
		return d, err
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return e.decide(tx, it), nil
	}
	if err := ctx.Err(); err != nil {
		return d, err
	}
	if len(r.Body) > 0 {
		if it, _, err := tx.WriteRequestBody(r.Body); err != nil {
			return d, fmt.Errorf("write body: %w", err)
		} else if it != nil {
			return e.decide(tx, it), nil
		}
	}
	if err := ctx.Err(); err != nil {
		return d, err
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		return d, fmt.Errorf("process body: %w", err)
	}
	return e.decide(tx, it), nil
}

var scoreRx = regexp.MustCompile(`Total Score: (\d+)`)

func (e *Engine) decide(tx types.Transaction, it *types.Interruption) engine.Decision {
	d := engine.Decision{RuleDetails: true}
	if it != nil {
		d.Interrupted = true
		d.Action = it.Action
		d.Status = it.Status
		if d.Status < 400 || d.Status > 599 {
			d.Status = 403
		}
	}
	for _, mr := range tx.MatchedRules() {
		meta := mr.Rule()
		msg := mr.Message()
		if l, ok := mr.(interface{ Log() bool }); (ok && !l.Log()) || msg == "" {
			continue // nolog bookkeeping rules
		}
		m := engine.Match{RuleID: meta.ID(), Message: msg, Severity: meta.Severity().String(), Phase: int(meta.Phase()), Tags: meta.Tags()}
		seen := map[string]bool{}
		for _, md := range mr.MatchedDatas() {
			t := md.Variable().Name()
			if k := md.Key(); k != "" {
				if len(k) > 128 {
					k = k[:128]
				}
				t += ":" + k
			}
			if !seen[t] && len(m.Targets) < 16 {
				seen[t] = true
				m.Targets = append(m.Targets, t)
			}
		}
		if meta.ID() == 949110 {
			if s := scoreRx.FindStringSubmatch(msg); s != nil {
				d.AnomalyScore, _ = strconv.Atoi(s[1])
			}
		}
		d.Matches = append(d.Matches, m)
	}
	return d
}
