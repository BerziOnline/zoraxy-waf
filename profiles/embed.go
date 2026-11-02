// Package profiles embeds the shipped service profile definitions.
package profiles

import "embed"

//go:embed *.json
var FS embed.FS
