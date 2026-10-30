//go:build no_fs_access

package coraza

// NoDiskSpool is true when built with no_fs_access: request bodies stay in
// memory (bounded by the 1 MiB inspection cap) and are never spooled.
const NoDiskSpool = true
