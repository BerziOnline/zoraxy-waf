package branding

import (
	"bytes"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestIconIsA512PNG(t *testing.T) {
	img, err := png.Decode(bytes.NewReader(Icon))
	if err != nil {
		t.Fatalf("embedded icon is not a PNG: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 512 || b.Dy() != 512 {
		t.Fatalf("icon is %dx%d, want 512x512", b.Dx(), b.Dy())
	}
}

func TestInstallWritesOnceAndRepairs(t *testing.T) {
	dir := t.TempDir()
	wrote, err := Install(dir)
	if err != nil || !wrote {
		t.Fatalf("first install: wrote=%v err=%v", wrote, err)
	}
	wrote, err = Install(dir)
	if err != nil || wrote {
		t.Fatalf("second install must be a no-op: wrote=%v err=%v", wrote, err)
	}
	path := filepath.Join(dir, "icon.png")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	wrote, err = Install(dir)
	if err != nil || !wrote {
		t.Fatalf("stale icon must be replaced: wrote=%v err=%v", wrote, err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, Icon) {
		t.Fatal("icon.png differs from the embedded icon")
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("temp file left behind")
	}
}
