// Package host: JDK home discovery, release-file parsing, CPU assessment,
// running-process scan and Java4Shell host-mode JSON assembly.
package host

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// JVM is one discovered JDK home.
type JVM struct {
	Path          string `json:"path"`
	Implementor   string `json:"implementor"`
	JavaVersion   string `json:"java_version"`
	VendorVersion string `json:"vendor_version,omitempty"`
	Status        string `json:"status"`
	Notes         string `json:"notes"`
}

// Process is one running JVM process.
type Process struct {
	PID            string `json:"pid"`
	User           string `json:"user,omitempty"`
	CmdlineSnippet string `json:"cmdline_snippet"`
	Status         string `json:"status"` // mitigated | vulnerable-no-mitigation | unknown-home
	JVMHome        string `json:"jvm_home,omitempty"`
}

// CPU is the CPU assessment block.
type CPU struct {
	Arch            string   `json:"arch"`
	Flags           []string `json:"flags"`
	VulnerableClass string   `json:"vulnerable_class"` // hw-vulnerable | hw-not-vulnerable | hw-unknown
}

// Report is the stable host-mode JSON schema.
type Report struct {
	HostInfo       map[string]string `json:"host_info"`
	CPU            CPU               `json:"cpu"`
	JVMs           []JVM             `json:"jvms"`
	Processes      []Process         `json:"processes"`
	ContainersHint bool              `json:"containers_hint"`
	ContainersNote string            `json:"containers_note,omitempty"`
	Summary        Summary           `json:"summary"`
	AssessmentNote string            `json:"assessment_note"`
}

type Summary struct {
	Total      int `json:"total"`
	Vulnerable int `json:"vulnerable"`
	Fixed      int `json:"fixed"`
	Mitigated  int `json:"mitigated"`
	Mystery    int `json:"mystery"`
}

// DiscoverDirs returns candidate JDK parent directories for the current OS.
func DiscoverDirs(goos string) []string {
	home, _ := os.UserHomeDir()
	switch goos {
	case "linux":
		dirs := []string{"/usr/lib/jvm", "/usr/java"}
		dirs = append(dirs, globDirs("/opt", "*")...)
		if home != "" {
			dirs = append(dirs, filepath.Join(home, ".sdkman/candidates/java"))
		}
		if jh := os.Getenv("JAVA_HOME"); jh != "" {
			dirs = append(dirs, jh)
		}
		return dirs
	case "darwin":
		libs := []string{"/Library/Java/JavaVirtualMachines",
			"/System/Library/Java/JavaVirtualMachines"}
		if home != "" {
			libs = append(libs, filepath.Join(home, "Library/Java/JavaVirtualMachines"))
		}
		dirs := append(libs, globDirs("/opt/homebrew/opt", "openjdk*")...)
		dirs = append(dirs, globDirs("/usr/local/opt", "openjdk*")...)
		// IDE-bundled JetBrains Runtimes (Android Studio, IntelliJ). One
		// glob level per app; apps without a jbr simply do not match.
		dirs = append(dirs, globDirs("/Applications", "*/Contents/jbr/Contents/Home")...)
		if jh := os.Getenv("JAVA_HOME"); jh != "" {
			dirs = append(dirs, jh)
		}
		return dirs
	case "windows":
		var dirs []string
		root := os.Getenv("ProgramFiles")
		if root == "" {
			root = `C:\Program Files`
		}
		for _, v := range []string{"Java", "Eclipse Adoptium", "Amazon Corretto",
			"Zulu", "BellSoft", "SapMachine", "Microsoft"} {
			dirs = append(dirs, filepath.Join(root, v))
		}
		if jh := os.Getenv("JAVA_HOME"); jh != "" {
			dirs = append(dirs, jh)
		}
		return dirs
	}
	return nil
}

func globDirs(parent, pattern string) []string {
	if parent == "" {
		return nil
	}
	matches, _ := filepath.Glob(filepath.Join(parent, pattern))
	var out []string
	for _, m := range matches {
		if fi, err := os.Stat(m); err == nil && fi.IsDir() {
			out = append(out, m)
		}
	}
	return out
}

// DiscoverHomes finds JDK home directories under dirs (test-injectable).
func DiscoverHomes(dirs []string) []string {
	var homes []string
	seen := map[string]bool{}
	add := func(p string) {
		p = filepath.Clean(p)
		if p == "" || seen[p] {
			return
		}
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			seen[p] = true
			homes = append(homes, p)
		}
	}
	for _, d := range dirs {
		if dirHasFile(d, "release") {
			// The listed directory is itself a JDK home (JAVA_HOME,
			// macOS app-bundle Contents/Home).
			add(d)
			continue
		}
		if strings.HasSuffix(d, " Contents") { // macOS framework layout
			add(d)
			continue
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			if !e.IsDir() {
				if t, _ := filepath.EvalSymlinks(p); t != "" {
					if fi, err := os.Stat(t); err != nil || !fi.IsDir() {
						continue
					}
				}
			}
			if runtime.GOOS == "darwin" && strings.HasSuffix(p, "JavaVirtualMachines") {
				// macOS Contents layout handled in the generic branch below.
				_ = p
			}

			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				// macOS: <base>/<id>/Contents/Home
				if runtime.GOOS == "darwin" && strings.HasSuffix(d, "JavaVirtualMachines") && dirHasFile(p, "Contents") {
					inner := filepath.Join(p, "Contents", "Home")
					if dirHasFile(inner, "release") {
						add(inner)
						continue
					}
				}
				if dirHasFile(p, "release") {
					add(p)
				} else {
					// one level deeper? check for release inside children
					for _, c := range []string{"Home", "jdk", "jdk-" + e.Name()} {
						inner := filepath.Join(p, c)
						if dirHasFile(inner, "release") {
							add(inner)
						}
					}
				}
			}
		}
	}
	if len(homes) == 0 {
		return []string{}
	}
	return homes
}

func dirHasEntry(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

// dirHasFile reports whether dir contains an entry named name (file OR
// directory — callers use it for "release" files and for macOS "Contents"
// directories alike).
func dirHasFile(dir, name string) bool {
	return dirHasEntry(dir, name)
}
