// Package brand: IONSEC lockup, header line and the open-source license
// acceptance gate for java4shell-detector (CVE-2026-114938).
package brand

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Tool identity. EULAVersion bumps force re-acceptance (state stores the
// version it accepted).
const (
	ToolName    = "java4shell-detector"
	Vendor      = "IONSEC"
	CVE         = "CVE-2026-114938"
	Version     = "1.0.0"
	License     = "AGPL-3.0"
	EULAVersion = "1.0"
)

// bannerWidth is the inner width of the hairline lockup box.
const bannerWidth = 62

// centered returns s padded to bannerWidth-2 (the inner box width),
// centered by runes (content may contain multi-byte glyphs), and truncated
// when longer.
func centered(s string) string {
	w := bannerWidth - 2
	r := []rune(s)
	if len(r) >= w {
		return string(r[:w])
	}
	left := (w - len(r)) / 2
	right := w - len(r) - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

// Lockup renders the plain-text hairline wordmark used by `version`.
// Box-drawing frame with a centered plain-text wordmark — no ASCII-art
// block banners.
func Lockup() string {
	var b strings.Builder
	b.WriteString("┌" + strings.Repeat("─", bannerWidth-2) + "┐\n")
	b.WriteString("|" + centered(inner(Vendor+" · "+ToolName)) + "|\n")
	b.WriteString("|" + centered(inner(CVE+" - OpenJDK Base64 inventory - v"+Version)) + "|\n")
	b.WriteString("├" + strings.Repeat("─", bannerWidth-2) + "┤\n")
	b.WriteString("|" + centered(inner(License+" free software - read-only inventory")) + "|\n")
	b.WriteString("|" + centered(inner("net mode never sends the CVE trigger")) + "|\n")
	b.WriteString("└" + strings.Repeat("─", bannerWidth-2) + "┘\n")
	b.WriteString("No warranty. First run asks license acceptance; see --show-eula.\n")
	return b.String()
}

// inner strips the box margins (2 chars) for centered().
func inner(s string) string { return s }

// boxLine renders "| <centered-to-width-2> |".

// HeaderLine is the single line prefixed to every text-format report.
func HeaderLine() string {
	return Vendor + " " + ToolName + " v" + Version + " - " + CVE + " - AGPL-3.0"
}

// EULAText is the full license-and-acceptance text shown by --show-eula and
// on the interactive first run.
func EULAText() string {
	return Lockup() + `
OPEN-SOURCE LICENSE AND ACCEPTANCE (v` + EULAVersion + `)

This tool is open source software, licensed under the GNU Affero General
Public License v3.0 (AGPL-3.0). You may run it, study its source, share it,
and modify it under the terms of that license. It is provided "AS IS",
WITHOUT WARRANTY OF ANY KIND, express or implied. Neither IONSEC nor the
authors are liable for any damage, downtime, or data loss arising from its
use.

By accepting, you confirm that:

  1. You run this tool only on systems and networks you are authorized to
     assess, and in line with your organization's policies and applicable
     law.

  2. The tool performs read-only inventory: host mode parses the local
     filesystem and process table; net mode performs inventory-only TCP,
     HTTP/HTTPS and Kafka-version probes. It NEVER sends the CVE-2026-114938
     trigger payload, because sending it can crash vulnerable services.

  3. Findings are version and configuration comparisons, not proof of
     exploitability. You remain responsible for remediation decisions.

State of acceptance is stored locally (per-user) as plain text:
  Linux/macOS  ~/.config/ionsec/` + ToolName + `/eula
  Windows      %APPDATA%\ionsec\` + ToolName + `\eula

Delete that file to clear acceptance. Bump EULA v` + EULAVersion + ` -> re-acceptance.
`
}

// statePath returns the per-user acceptance file location.
func statePath() (string, error) {
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("APPDATA")
		if base == "" {
			return "", errors.New("%APPDATA% is not set; cannot store license acceptance")
		}
	default:
		base = os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".config")
		}
	}
	return filepath.Join(base, "ionsec", ToolName, "eula"), nil
}

const stateMarker = "ACCEPTED_EULA="

// AcceptedOn reports whether the stored state accepted eulaVersion. dir can
// be injected in tests.
func AcceptedOn(dir string, eulaVersion string) bool {
	data, err := os.ReadFile(dir)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, stateMarker) {
			return strings.TrimSpace(strings.TrimPrefix(line, stateMarker)) == eulaVersion
		}
	}
	return false
}

// Accepted reports acceptance for the current EULAVersion using the real
// per-user state path.
func Accepted() (bool, error) {
	p, err := statePath()
	if err != nil {
		return false, err
	}
	return AcceptedOn(p, EULAVersion), nil
}

// AcceptAt writes the acceptance record. dir can be injected in tests.
func AcceptAt(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	rec := fmt.Sprintf("%s%s\nACCEPTED_AT=%s\nTOOL=%s/%s\n",
		stateMarker, EULAVersion, time.Now().UTC().Format(time.RFC3339), Vendor, ToolName)
	return os.WriteFile(dir, []byte(rec), 0o600)
}

// Accept writes the record to the real per-user state path.
func Accept() error {
	p, err := statePath()
	if err != nil {
		return err
	}
	return AcceptAt(p)
}

// EnvAccepted reports IONSEC_EULA_ACCEPT in (1|true|yes|y).
func envAccepted() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("IONSEC_EULA_ACCEPT")))
	switch v {
	case "1", "true", "yes", "y":
		return true
	}
	return false
}

// GateOpts carries the injectable inputs for Ensure.
type GateOpts struct {
	AcceptFlag  bool      // --accept-eula passed
	Interactive bool      // stdin is a TTY
	Stdin       io.Reader // prompt input (tests inject strings.NewReader)
	Stderr      io.Writer // prompt/EULA output
	StateDir    string    // empty -> real per-user path
}

// Ensure blocks execution until the open-source terms are accepted.
// Priority: already accepted -> explicit flag/env/prompt.
func Ensure(o GateOpts) error {
	dir := o.StateDir
	if dir == "" {
		p, err := statePath()
		if err != nil {
			return err
		}
		dir = p
	}
	// 1. Already accepted on file (any prior run).
	if AcceptedOn(dir, EULAVersion) {
		return nil
	}
	// 2. Explicit acceptance: flag or CI env var. Persists for next runs.
	if o.AcceptFlag || envAccepted() {
		if err := AcceptAt(dir); err != nil {
			return fmt.Errorf("could not store acceptance: %w", err)
		}
		fmt.Fprintf(o.Stderr, "%s: open-source license accepted (stored: %s)\n",
			ToolName, dir)
		return nil
	}
	// 3. Interactive prompt on a real terminal.
	if o.Interactive && o.Stdin != nil && o.Stderr != nil {
		fmt.Fprint(o.Stderr, EULAText())
		fmt.Fprintf(o.Stderr, "Accept the license terms to continue? [y/N] ")
		var line string
		if _, err := fmt.Fscanln(o.Stdin, &line); err == nil {
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "y", "yes":
				if err := AcceptAt(dir); err != nil {
					return fmt.Errorf("could not store acceptance: %w", err)
				}
				fmt.Fprintf(o.Stderr, "%s: license accepted (stored: %s)\n", ToolName, dir)
				return nil
			}
		}
		return errors.New("license terms not accepted; nothing was run")
	}
	// 4. Non-interactive and not accepted: refuse with machine-friendly args.
	return errors.New("open-source license acceptance required before first run: " +
		"re-run with --accept-eula, set IONSEC_EULA_ACCEPT=1 (CI), or accept interactively; " +
		"read the full terms with --show-eula (" + License + ")")
}
