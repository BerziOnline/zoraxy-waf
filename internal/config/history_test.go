package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDiffAndHistoryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a := Default()
	b := a.Clone()
	b.Mode = "block"
	b.CrowdSec.APIKey = "secret-value"
	b.Hosts["shop.example"] = HostOverride{Mode: "report"}
	b.Revision = 1
	changes := Diff(a, b)
	got := map[string]Change{}
	for _, c := range changes {
		got[c.Field] = c
	}
	if c := got["mode"]; c.From != "off" || c.To != "block" {
		t.Fatalf("mode change wrong: %+v", c)
	}
	if c, ok := got["crowdsec.api_key"]; !ok || c.To != "changed" || c.From != "" {
		t.Fatalf("secret must be described, not printed: %+v", c)
	}
	for _, c := range changes {
		if c.From == "secret-value" || c.To == "secret-value" {
			t.Fatalf("secret leaked in change list: %+v", c)
		}
	}
	if _, ok := got["hosts.shop.example.mode"]; !ok {
		t.Fatalf("host addition missing: %v", changes)
	}
	if _, ok := got["revision"]; ok {
		t.Fatalf("revision must never be listed as a change")
	}
	if err := AppendHistory(dir, HistoryEntry{Time: time.Unix(100, 0).UTC(), Revision: 1, Changes: changes, Snapshot: b}); err != nil {
		t.Fatal(err)
	}
	c := b.Clone()
	c.Mode = "report"
	c.Revision = 2
	if err := AppendHistory(dir, HistoryEntry{Time: time.Unix(200, 0).UTC(), Revision: 2, Changes: Diff(b, c), Snapshot: c}); err != nil {
		t.Fatal(err)
	}
	list, err := History(dir, 10)
	if err != nil || len(list) != 2 || list[0].Revision != 2 || list[1].Revision != 1 {
		t.Fatalf("history listing wrong: %v %v", list, err)
	}
	snap, err := Snapshot(dir, 1)
	if err != nil || snap.Mode != "block" || snap.CrowdSec.APIKey != "secret-value" {
		t.Fatalf("snapshot of revision 1 wrong: %+v %v", snap, err)
	}
	if _, err = Snapshot(dir, 9); err == nil {
		t.Fatal("unknown revision must fail")
	}
}

func TestHistoryCompactionAndTornLine(t *testing.T) {
	dir := t.TempDir()
	cfg := Default()
	for i := 1; i <= historyKeep+5; i++ {
		cfg.Revision = uint64(i)
		if err := AppendHistory(dir, HistoryEntry{Time: time.Now(), Revision: uint64(i), Snapshot: cfg}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := readHistory(filepath.Join(dir, historyFile))
	if err != nil || len(entries) != historyKeep || entries[0].Revision != 6 {
		t.Fatalf("compaction wrong: %d entries, first %d, err %v", len(entries), entries[0].Revision, err)
	}
	// A torn trailing line (crash mid-write) must not hide the valid entries.
	f, _ := openAppend(filepath.Join(dir, historyFile))
	f.WriteString(`{"time":"2026-01-01T00:00:00Z","revision":999,"snap`)
	f.Close()
	list, err := History(dir, 1)
	if err != nil || len(list) != 1 || list[0].Revision != uint64(historyKeep+5) {
		t.Fatalf("torn line handling wrong: %v %v", list, err)
	}
}
