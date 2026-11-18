// Package verdict classifies Java versions against CVE-2026-114938 (Java4Shell).
package verdict

import (
	"fmt"
	"strconv"
	"strings"
)

// Status values used in JSON output.
const (
	StatusVulnerable  = "vulnerable"
	StatusFixed       = "fixed"
	StatusNotAffected = "not_affected"
	StatusMystery     = "mystery"
	StatusMitigated   = "mitigated-runtime"
)

// Affected majors and their fixed 4-segment versions.
var fixedVersions = map[int]version{
	17: {17, 0, 21, 1, 0},
	21: {21, 0, 13, 1, 0},
	25: {25, 0, 5, 1, 0},
	27: {27, 0, 1, 1, 0},
}

var firstAffected17 = version{17, 0, 6, 0, 0}

type version [5]int

func (v version) String() string {
	parts := make([]string, 5)
	for i, s := range v {
		parts[i] = strconv.Itoa(s)
	}
	return strings.Join(parts, ".")
}

func (v version) lt(o version) bool {
	for i := 0; i < 5; i++ {
		if v[i] != o[i] {
			return v[i] < o[i]
		}
	}
	return false // equal
}

// ParseVersion converts a JAVA_VERSION string (17.0.21, 1.8.0_511,
// 17.0.21.1+4 ...) into numeric segments padded to 5. Returns error for
// anything unparseable.
func ParseVersion(s string) (version, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "build ")
	if i := strings.IndexAny(s, "+-"); i >= 0 {
		// keep the main part (17.0.21.1+35 -> 17.0.21.1); but keep the
		// '+' segment if it is numeric like 1.8.0_511-b31 handled below.
		s = s[:i]
	}
	var v version
	count := 0
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '_' }) {
		n, err := strconv.Atoi(tok)
		if err != nil {
			return version{}, fmt.Errorf("unparseable token %q in %q", tok, s)
		}
		if count >= 5 {
			return version{}, fmt.Errorf("too many segments in %q", s)
		}
		v[count] = n
		count++
	}
	if count == 0 {
		return version{}, fmt.Errorf("no numeric segments in %q", s)
	}
	// Legacy 1.8.0_x: major is effectively 8.
	if v[0] == 1 && v[1] == 8 {
		v = version{8, 0, v[2], v[3], v[4]}
	}
	return v, nil
}

// Classify applies the Java4Shell version rules to a parsed release file.
// implementorVersion may be empty.
func Classify(javaVersion string, implementorVersion string) (status string, note string) {
	if javaVersion == "" {
		return StatusMystery, "JAVA_VERSION missing from release file"
	}
	v, err := ParseVersion(javaVersion)
	if err != nil {
		return StatusMystery, "unparseable JAVA_VERSION: " + javaVersion
	}
	major := v[0]
	if major == 8 {
		if javaVersion == "1.8.0_511" && strings.Contains(implementorVersion, "b33-perf") {
			return StatusVulnerable, "Oracle 8u511b33-perf performance build affected"
		}
		return StatusNotAffected, "8u branch affected only in Oracle 8u511b33-perf"
	}
	fixed, ok := fixedVersions[major]
	if !ok {
		if major < 17 {
			return StatusNotAffected, fmt.Sprintf("major %d predates 17.0.6 and lacks the AVX-512 intrinsic", major)
		}
		// Non-LTS EOL branches (18-20, 22-24, ...) branch from mainline
		// after 17.0.6 and carry the affected intrinsic; no vendor fix is
		// published for them. The advisory's plain wording is "OpenJDK
		// from version 17.0.6 or newer", so report vulnerable until
		// migration to a patched LTS. JFrog enumerates only the LTS
		// branches (17/21/25/27) because enterprises run those.
		return StatusVulnerable, fmt.Sprintf("major %d branches from mainline after 17.0.6 (advisory: 17.0.6 or newer); EOL branch has no vendor fix — migrate to patched LTS 17.0.21.1+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+", major)
	}
	if major == 17 && v.lt(firstAffected17) {
		return StatusNotAffected, "17.x below 17.0.6 lacks the AVX-512 intrinsic"
	}
	if v.lt(fixed) {
		return StatusVulnerable, fmt.Sprintf("%s < fixed %s", v.String(), fixed.String())
	}
	return StatusFixed, fmt.Sprintf("%s >= fixed %s", v.String(), fixed.String())
}

// OracleInternalNote flags Oracle CPU-internal builds (4th segment 0 with a
// 5th segment) which are listed as vulnerable despite looking like the fixed
// 3-segment version. Classify already handles this numerically:
// 17.0.21.0.3 < 17.0.21.1.0.
func IsOracleInternal(javaVersion string) bool {
	v, err := ParseVersion(javaVersion)
	if err != nil {
		return false
	}
	return v[3] == 0 && hasExplicitSegment(javaVersion, 5)
}

func hasExplicitSegment(s string, want int) bool {
	return len(strings.FieldsFunc(strings.TrimSpace(trimBuildSuffix(s)),
		func(r rune) bool { return r == '.' || r == '_' })) >= want
}

func trimBuildSuffix(s string) string {
	if i := strings.IndexAny(s, "+-"); i >= 0 {
		return s[:i]
	}
	return s
}
