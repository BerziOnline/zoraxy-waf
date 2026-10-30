package config

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// LegacySpeedGCTarget is the GC target the removed boolean "speed_mode" stood for.
const LegacySpeedGCTarget = 200

// migrateLegacy rewrites config files written by earlier plugin versions so the
// strict decoder (DisallowUnknownFields) accepts them. Without it an old file
// would fail to load and the plugin would start on defaults, dropping the
// stored policy.
//
//	speed_mode: true  -> gc_target 200, unless gc_target is set explicitly
//	speed_mode: false -> removed (gc_target keeps its default)
//
// Files without legacy fields are returned unchanged, byte for byte.
func migrateLegacy(data []byte) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		// Not an object: let the strict decoder report the real error.
		return data, nil
	}
	speed, ok := raw["speed_mode"]
	if !ok {
		return data, nil
	}
	var on bool
	if err := json.Unmarshal(speed, &on); err != nil {
		return nil, fmt.Errorf("legacy field speed_mode: %w", err)
	}
	delete(raw, "speed_mode")
	if _, explicit := raw["gc_target"]; on && !explicit {
		raw["gc_target"] = json.RawMessage(fmt.Sprint(LegacySpeedGCTarget))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
