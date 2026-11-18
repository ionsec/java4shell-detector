//go:build !windows

package host

// registryHomes is a no-op outside windows (registry scan is documented as
// windows-only discovery).
func registryHomes(goos string) []string { return nil }
