package wire

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// corePayload mirrors what the Zoraxy core encodes today: the flat
// DynamicSniffForwardRequest fields plus body (base64) and body_truncated.
const corePayload = `{
 "method":"POST","hostname":"shop.example","url":"/login?x=1",
 "header":{"Content-Type":["application/x-www-form-urlencoded"],"Cookie":["a=b"]},
 "remote_addr":"127.0.0.1:5555","client_ip":"203.0.113.9","host":"shop.example",
 "request_uri":"/login?x=1","proto":"HTTP/1.1","proto_major":1,"proto_minor":1,
 "body":"dXNlcj1hZG1pbg==","body_truncated":false,
 "protocol_version":1,"route_id":"shop.example","some_future_field":{"x":1}
}`

func TestDecodeInspectPayloadCoreShape(t *testing.T) {
	p, err := DecodeInspectPayload(strings.NewReader(corePayload), 1<<20)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Method != "POST" || p.ClientIP != "203.0.113.9" || p.RequestURI != "/login?x=1" {
		t.Fatalf("metadata not decoded: %+v", p)
	}
	if string(p.Body) != "user=admin" || p.BodyTruncated {
		t.Fatalf("body not decoded: %q truncated=%v", p.Body, p.BodyTruncated)
	}
	if p.ProtocolVersion != 1 || p.RouteID != "shop.example" {
		t.Fatalf("v1 fields not decoded: %+v", p)
	}
	if p.Header["Cookie"][0] != "a=b" {
		t.Fatalf("headers not decoded")
	}
}

func TestDecodeInspectPayloadLegacyAndNullBody(t *testing.T) {
	legacy := `{"method":"GET","host":"a.example","request_uri":"/","proto":"HTTP/1.1","header":null,"body":null,"body_truncated":false}`
	p, err := DecodeInspectPayload(strings.NewReader(legacy), 1<<20)
	if err != nil {
		t.Fatalf("legacy payload rejected: %v", err)
	}
	if p.ProtocolVersion != 0 || len(p.Body) != 0 {
		t.Fatalf("unexpected legacy decode %+v", p)
	}
}

func TestDecodeInspectPayloadRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"empty":            ``,
		"not json":         `hello`,
		"trailing data":    `{"method":"GET","request_uri":"/"} {"x":1}`,
		"future protocol":  `{"method":"GET","request_uri":"/","protocol_version":2}`,
		"missing method":   `{"request_uri":"/"}`,
		"bad method":       `{"method":"G T","request_uri":"/"}`,
		"missing uri":      `{"method":"GET"}`,
		"bad body base64":  `{"method":"GET","request_uri":"/","body":"!!!"}`,
		"wrong field type": `{"method":"GET","request_uri":"/","body_truncated":"yes"}`,
	}
	for name, in := range cases {
		if _, err := DecodeInspectPayload(strings.NewReader(in), 1<<20); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestDecodeInspectPayloadSizeLimit(t *testing.T) {
	big := `{"method":"GET","request_uri":"/","body":"` + strings.Repeat("A", 4096) + `"}`
	if _, err := DecodeInspectPayload(strings.NewReader(big), 1024); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func TestResultJSONKeys(t *testing.T) {
	b, _ := json.Marshal(InspectResult{Action: "deny", Status: 403, Reason: "Blocked", EventID: "e1"})
	want := `{"action":"deny","status":403,"reason":"Blocked","event_id":"e1"}`
	if string(b) != want {
		t.Fatalf("got %s want %s", b, want)
	}
	b, _ = json.Marshal(InspectResult{Action: "allow"})
	if string(b) != `{"action":"allow"}` {
		t.Fatalf("allow encoding %s", b)
	}
}

func TestPolicyJSONExactKeys(t *testing.T) {
	p := Policy{Mode: "report", MaxBodyKB: 64, BodyTimeoutMS: 5000}
	b, _ := json.Marshal(p.Normalized())
	want := `{"mode":"report","fail_closed":false,"invert_failure_hosts":[],"max_body_kb":64,"body_timeout_ms":5000,"hosts":{}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	p.Hosts = map[string]HostPolicy{"a.example": {Mode: "block", MaxBodyKB: 128}}
	b, _ = json.Marshal(p.Normalized())
	if !bytes.Contains(b, []byte(`"hosts":{"a.example":{"mode":"block","max_body_kb":128}}`)) {
		t.Fatalf("host override encoding %s", b)
	}
}

func TestIntroSpectKeys(t *testing.T) {
	b, _ := json.Marshal(IntroSpect{ID: "x", RequestInspect: "/inspect", RequestInspectPolicy: "/policy", UIPath: "/ui/", RequestInspectMaxBody: 64})
	for _, k := range []string{`"request_inspect":"/inspect"`, `"request_inspect_policy":"/policy"`, `"ui_path":"/ui/"`, `"request_inspect_max_body":64`, `"static_capture_paths"`, `"permitted_api_endpoints"`, `"version_major"`} {
		if !bytes.Contains(b, []byte(k)) {
			t.Errorf("introspect JSON missing %s: %s", k, b)
		}
	}
}

func TestParseConfigureArgs(t *testing.T) {
	spec, err := ParseConfigureArgs([]string{"bin", `-configure={"port":18482,"runtime_const":{"zoraxy_version":"3.3.5"},"api_key":"k","zoraxy_port":18400}`})
	if err != nil || spec.Port != 18482 || spec.ZoraxyPort != 18400 || spec.APIKey != "k" {
		t.Fatalf("configure= form: %+v %v", spec, err)
	}
	spec, err = ParseConfigureArgs([]string{"bin", "-configure", `{"port":18483}`})
	if err != nil || spec.Port != 18483 {
		t.Fatalf("separate arg form: %+v %v", spec, err)
	}
	if _, err := ParseConfigureArgs([]string{"bin"}); err == nil {
		t.Fatal("missing -configure accepted")
	}
	if _, err := ParseConfigureArgs([]string{"bin", `-configure={"port":0}`}); err == nil {
		t.Fatal("invalid port accepted")
	}
}
