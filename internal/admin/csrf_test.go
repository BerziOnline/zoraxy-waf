package admin

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// gorilla/csrf masks the same 32-byte session token freshly on each request.
func maskedFixture(raw, mask byte) string {
	b := make([]byte, 64)
	for i := 0; i < 32; i++ {
		b[i] = mask
		b[32+i] = raw ^ mask
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestMutationAcceptsFreshMaskOfSameSessionToken(t *testing.T) {
	s, h := setup(t)
	c := s.Current()
	c.Mode = "report"
	body, _ := json.Marshal(c)
	pageToken := maskedFixture(7, 11)
	requestToken := maskedFixture(7, 23)
	w := call(h, "PUT", "/ui/api/config", string(body), requestToken, pageToken)
	if w.Code != 200 || s.Current().Mode != "report" {
		t.Fatalf("same session with different masks rejected: %d %s", w.Code, w.Body)
	}
}

func TestMutationRejectsOtherSessionMaskedToken(t *testing.T) {
	s, h := setup(t)
	body, _ := json.Marshal(s.Current())
	for _, echo := range []string{maskedFixture(8, 11), "not-a-token", base64.StdEncoding.EncodeToString(make([]byte, 63))} {
		w := call(h, "PUT", "/ui/api/config", string(body), maskedFixture(7, 23), echo)
		if w.Code != 403 {
			t.Fatalf("foreign/malformed token accepted: %d", w.Code)
		}
	}
}

func TestMutationRejectsMissingTrustedSessionToken(t *testing.T) {
	s, h := setup(t)
	body, _ := json.Marshal(s.Current())
	echo := maskedFixture(7, 23)
	for _, trusted := range []string{"", "missing-csrf-token"} {
		w := call(h, "PUT", "/ui/api/config", string(body), trusted, echo)
		if w.Code != 403 {
			t.Fatalf("mutation without trusted Zoraxy session token accepted (%q): %d", trusted, w.Code)
		}
	}
}
