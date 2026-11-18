package host

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ionsec/java4shell-detector/internal/verdict"
)

// ParseRelease parses a JDK `release` file: KEY="VALUE" / KEY=VALUE lines.
func ParseRelease(text string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.Index(line, "=")
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		val = strings.Trim(val, `"`)
		m[key] = val
	}
	return m
}

// LoadJVM builds a JVM record from a home directory. execVersion is the
// optional output of `java -version` probing when no release file exists.
func LoadJVM(home string, execVersion func(string) (string, bool)) JVM {
	j := JVM{Path: home}
	data, err := os.ReadFile(filepath.Join(home, "release"))
	if err != nil {
		j.Status = "mystery"
		j.Notes = "no release file"
		if execVersion != nil {
			if out, ok := execVersion(home); ok {
				if v := extractJavaVersionLine(out); v != "" {
					j.JavaVersion = v
					j.Status, j.Notes = verdict.Classify(v, "")
				}
				j.Notes += " (version probed via java -version)"
			}
		}
		return j
	}
	m := ParseRelease(string(data))
	j.Implementor = m["IMPLEMENTOR"]
	j.VendorVersion = m["IMPLEMENTOR_VERSION"]
	j.JavaVersion = coalesce(m["JAVA_VERSION"], firstNonEmpty(m["OPENJDK_VERSION"], m["JAVA_VERSION_FULL"]))
	j.Status, j.Notes = verdict.Classify(j.JavaVersion, j.VendorVersion)
	return j
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// extractJavaVersionLine pulls the version token out of `java -version`
// stderr output (e.g. `openjdk version "17.0.8" 2023-07-18`).
func extractJavaVersionLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "version") {
			if i := strings.Index(line, `"`); i >= 0 {
				if j := strings.Index(line[i+1:], `"`); j >= 0 {
					return line[i+1 : i+1+j]
				}
			}
		}
	}
	return ""
}

// RunJavaVersion execs `java -version` in home/bin (only called with
// --probe-java-version).
func RunJavaVersion(home string) (string, bool) {
	var cmd *exec.Cmd
	if _, err := os.Stat(filepath.Join(home, "bin", "java")); err == nil {
		cmd = exec.Command(filepath.Join(home, "bin", "java"), "-version")
	} else if _, err := os.Stat(filepath.Join(home, "bin", "java.exe")); err == nil {
		cmd = exec.Command(filepath.Join(home, "bin", "java.exe"), "-version")
	} else {
		return "", false
	}
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", false
	}
	return string(out), true
}
