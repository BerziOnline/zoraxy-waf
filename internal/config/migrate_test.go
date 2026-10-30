package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// legacyFile writes a config saved by a plugin version that still had the
// boolean speed_mode, with a non-default policy that must survive the load.
func legacyFile(t *testing.T, extra string) string {
	t.Helper()
	c := Default()
	c.Mode = ModeBlock
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw, "gc_target")
	b, _ = json.Marshal(raw)
	s := strings.TrimSuffix(string(b), "}") + "," + extra + "}"
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadMigratesLegacySpeedMode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra string
		want  int
	}{
		{"speed on", `"speed_mode":true`, LegacySpeedGCTarget},
		{"speed off", `"speed_mode":false`, Default().GCTarget},
		{"explicit target wins", `"speed_mode":true,"gc_target":800`, 800},
		{"explicit target with off", `"speed_mode":false,"gc_target":100`, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := legacyFile(t, tc.extra)
			c, err := Load(path)
			if err != nil {
				t.Fatalf("legacy config rejected: %v", err)
			}
			if c.GCTarget != tc.want {
				t.Fatalf("gc_target = %d, want %d", c.GCTarget, tc.want)
			}
			if c.Mode != ModeBlock {
				t.Fatalf("stored policy lost: mode %q", c.Mode)
			}
			// Re-save drops the legacy field; the new file loads unchanged.
			if err := Save(path, c); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(path)
			if strings.Contains(string(b), "speed_mode") {
				t.Fatal("legacy field written back")
			}
			again, err := Load(path)
			if err != nil || again.GCTarget != tc.want || again.Mode != ModeBlock {
				t.Fatalf("re-saved config: %+v %v", again.GCTarget, err)
			}
		})
	}
}

func TestLoadRejectsMalformedLegacySpeedMode(t *testing.T) {
	path := legacyFile(t, `"speed_mode":"yes"`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "speed_mode") {
		t.Fatalf("want speed_mode error, got %v", err)
	}
}

func TestMigrateLegacyLeavesCurrentFilesUntouched(t *testing.T) {
	b, _ := json.Marshal(Default())
	out, err := migrateLegacy(b)
	if err != nil || string(out) != string(b) {
		t.Fatalf("current file changed: %v", err)
	}
	if _, err := migrateLegacy([]byte("not json")); err != nil {
		t.Fatalf("garbage must reach the strict decoder, got %v", err)
	}
}
