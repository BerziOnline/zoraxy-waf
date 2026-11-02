package learning

import (
	"strings"
	"testing"
	"time"
)

func TestProfilePathEvidencePersistsWithoutCredentials(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir)
	now := time.Now()
	s.ObservePath("chat.example.test", "/api/v4/posts?token=private", false, now)
	if len(s.Hosts()) != 0 {
		t.Fatal("scanner paths must not become detection evidence")
	}
	for i := 0; i < 3; i++ {
		s.ObservePath("chat.example.test", "/api/v4/posts?token=private", true, now)
	}
	snap := s.Snapshot()
	for p, n := range snap["chat.example.test"].Paths {
		if strings.Contains(p, "?") || n != 3 {
			t.Fatal(p, n)
		}
	}
	h := snap["chat.example.test"]
	h.Paths["/api/v4/posts"] = 100
	if s.Snapshot()["chat.example.test"].Paths["/api/v4/posts"] != 3 {
		t.Fatal("snapshot paths alias live store")
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if Open(dir).Snapshot()["chat.example.test"].Paths["/api/v4/posts"] != 3 {
		t.Fatal("path evidence not durable")
	}
}
