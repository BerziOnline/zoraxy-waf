//go:build !no_fs_access

package coraza

// NoDiskSpool is false when built without the no_fs_access tag: Coraza may
// then write multipart file parts to the temp directory.
const NoDiskSpool = false
