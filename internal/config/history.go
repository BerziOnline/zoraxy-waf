package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Change history: every saved revision is appended to history.jsonl with a
// human-readable list of what changed and the full snapshot, so an admin can
// see who-changed-what (by time) and roll back to any earlier revision.
// The file lives next to config.json with the same permissions; secrets are
// only ever described ("changed"), never printed in the change list.

const (
	historyFile = "history.jsonl"
	historyKeep = 200 // revisions kept on disk (oldest are dropped on compaction)
)

type Change struct {
	Field string `json:"field"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
}

type HistoryEntry struct {
	Time     time.Time `json:"time"`
	Revision uint64    `json:"revision"`
	Changes  []Change  `json:"changes"`
	Snapshot Config    `json:"snapshot"`
}

// PublicHistoryEntry is what the UI lists: no snapshot, no secret values.
type PublicHistoryEntry struct {
	Time     time.Time `json:"time"`
	Revision uint64    `json:"revision"`
	Changes  []Change  `json:"changes"`
}

var secretFields = map[string]bool{"crowdsec.api_key": true}

// Diff lists the fields that differ between two configurations as flat
// dotted paths ("hosts.shop.example.mode"), with values rendered as short
// strings. Secret fields are reported without values.
func Diff(old, new Config) []Change {
	a, b := flatten(old), flatten(new)
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var out []Change
	for k := range keys {
		if k == "revision" || a[k] == b[k] {
			continue
		}
		c := Change{Field: k}
		if secretFields[k] {
			c.From, c.To = "", "changed"
		} else {
			c.From, c.To = a[k], b[k]
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

func flatten(c Config) map[string]string {
	raw, _ := json.Marshal(c)
	var v any
	_ = json.Unmarshal(raw, &v)
	out := map[string]string{}
	walk("", v, out)
	return out
}

func walk(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			out[prefix] = "{}"
			return
		}
		for k, val := range t {
			walk(join(prefix, k), val, out)
		}
	case []any:
		if len(t) == 0 {
			out[prefix] = "[]"
			return
		}
		// Lists are rendered as one value so an added entry reads as one change.
		parts := make([]string, 0, len(t))
		for _, val := range t {
			b, _ := json.Marshal(val)
			parts = append(parts, string(b))
		}
		out[prefix] = strings.Join(parts, ", ")
	case nil:
		out[prefix] = ""
	default:
		b, _ := json.Marshal(t)
		out[prefix] = strings.Trim(string(b), `"`)
	}
}

func join(prefix, k string) string {
	if prefix == "" {
		return k
	}
	return prefix + "." + k
}

// AppendHistory records a saved revision. Failures are returned but callers
// treat them as non-fatal: the configuration itself is already saved.
func AppendHistory(dir string, entry HistoryEntry) error {
	path := filepath.Join(dir, historyFile)
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	f, err := openAppend(path)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return compactHistory(path)
}

func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

func compactHistory(path string) error {
	entries, err := readHistory(path)
	if err != nil || len(entries) <= historyKeep {
		return err
	}
	entries = entries[len(entries)-historyKeep:]
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, e := range entries {
		line, _ := json.Marshal(e)
		w.Write(append(line, '\n'))
	}
	if err = w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readHistory(path string) ([]HistoryEntry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []HistoryEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for sc.Scan() {
		var e HistoryEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue // a torn line (crash mid-write) must not hide the rest
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// History lists the newest entries first, without snapshots.
func History(dir string, limit int) ([]PublicHistoryEntry, error) {
	entries, err := readHistory(filepath.Join(dir, historyFile))
	if err != nil {
		return nil, err
	}
	out := make([]PublicHistoryEntry, 0, len(entries))
	for i := len(entries) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		e := entries[i]
		out = append(out, PublicHistoryEntry{Time: e.Time, Revision: e.Revision, Changes: e.Changes})
	}
	return out, nil
}

// Snapshot returns the configuration as it was saved at the given revision.
func Snapshot(dir string, revision uint64) (Config, error) {
	entries, err := readHistory(filepath.Join(dir, historyFile))
	if err != nil {
		return Config{}, err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Revision == revision {
			return entries[i].Snapshot, nil
		}
	}
	return Config{}, fmt.Errorf("revision %d is not in the history", revision)
}
