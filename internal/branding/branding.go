// Package branding ships the plugin icon and installs it where Zoraxy looks for it.
package branding

import (
	"bytes"
	_ "embed"
	"errors"
	"os"
	"path/filepath"
)

// Icon is the Zoraxy WAF logo (concept A: Zoraxy's own mark inside a shield), 512x512 PNG.
//
//go:embed icon.png
var Icon []byte

// Install writes icon.png into dir (the plugin root, next to the executable) when
// the file is missing or differs. Zoraxy serves exactly <plugin root>/icon.png in
// its plugin list and sidebar; without it the generic placeholder is shown.
// Returns false when nothing had to be written.
func Install(dir string) (bool, error) {
	path := filepath.Join(dir, "icon.png")
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, Icon) {
		return false, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, Icon, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, nil
}
