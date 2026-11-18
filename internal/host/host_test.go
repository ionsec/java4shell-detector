package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRelease(t *testing.T) {
	m := ParseRelease(`IMPLEMENTOR="Eclipse Temurin"
JAVA_VERSION="17.0.9"
IMPLEMENTOR_VERSION="Temurin-17.0.9+8"
JAVA_VERSION_FULL=17.0.9+99
# comment
`)
	if m["IMPLEMENTOR"] != "Eclipse Temurin" || m["JAVA_VERSION"] != "17.0.9" ||
		m["IMPLEMENTOR_VERSION"] != "Temurin-17.0.9+8" || m["JAVA_VERSION_FULL"] != "17.0.9+99" {
		t.Fatalf("parsed map wrong: %v", m)
	}
}

func TestDiscoverHomesFixtureTree(t *testing.T) {
	homes := DiscoverHomes([]string{td("jvms")})
	if len(homes) == 0 {
		t.Fatal("no homes discovered")
	}
	// mystery home is a dir without bin but with release -> found
	found := map[string]bool{}
	for _, h := range homes {
		found[h[strings.LastIndex(h, "/")+1:]] = true
	}
	for _, want := range []string{"temurin-17.0.9-vuln", "corretto-17.0.21.1.2-fixed",
		"oracle-8-b33perf", "jdk11-naffected", "broken-mystery"} {
		if !found[want] {
			t.Fatalf("missing %q in %v", want, found)
		}
	}
}

func TestLoadJVMClassification(t *testing.T) {
	tests := []struct {
		dir, wantStatus, wantVersion string
	}{
		{td("jvms/temurin-17.0.9-vuln"), "vulnerable", "17.0.9"},
		{td("jvms/corretto-17.0.21.1.2-fixed"), "fixed", "17.0.21.1.2"},
		{td("jvms/oracle-8-b33perf"), "vulnerable", "1.8.0_511"},
		{td("jvms/jdk11-naffected"), "not_affected", "11.0.24"},
		{td("jvms/broken-mystery"), "mystery", "banana"},
		{td("jvms/oracle-17.0.21.0.3-vuln"), "vulnerable", "17.0.21.0.3"},
		{td("jvms/jdk17.0.21-nofix-vuln"), "vulnerable", "17.0.21"},
	}
	for _, tt := range tests {
		j := LoadJVM(tt.dir, nil)
		if j.Status != tt.wantStatus || j.JavaVersion != tt.wantVersion {
			t.Errorf("%s: got status=%s version=%s, want %s/%s",
				tt.dir, j.Status, j.JavaVersion, tt.wantStatus, tt.wantVersion)
		}
	}
	if j := LoadJVM(td("jvms/oracle-8-b33perf"), nil); j.VendorVersion != "1.8.0_511-b33-perf" {
		t.Errorf("IMPLEMENTOR_VERSION not picked up: %q", j.VendorVersion)
	}
	if j := LoadJVM(td("jvms/nonexistent"), nil); j.Status != "mystery" {
		t.Errorf("missing dir should be mystery, got %q", j.Status)
	}
}

func TestExtractJavaVersionLine(t *testing.T) {
	out := `openjdk version "21.0.12" 2026-10-21
OpenJDK Runtime Environment Temurin-21.0.12`
	if v := extractJavaVersionLine(out); v != "21.0.12" {
		t.Fatalf("got %q", v)
	}
}

func TestCPUAssessLinuxFixtureFlags(t *testing.T) {
	full := []string{"fpu", "avx512f", "avx512bw", "avx512vbmi", "bmi2", "sse2"}
	c := CPUAssess("linux", "amd64", func() ([]string, error) { return full, nil }, nil)
	if c.VulnerableClass != "hw-vulnerable" {
		t.Fatalf("want hw-vulnerable, got %s (%v)", c.VulnerableClass, c.Flags)
	}
	missing := []string{"fpu", "avx512f", "avx512bw", "bmi2"}
	c = CPUAssess("linux", "amd64", func() ([]string, error) { return missing, nil }, nil)
	if c.VulnerableClass != "hw-not-vulnerable" {
		t.Fatalf("want hw-not-vulnerable, got %s", c.VulnerableClass)
	}
	c = CPUAssess("linux", "arm64", nil, nil)
	if c.VulnerableClass != "hw-not-vulnerable" {
		t.Fatalf("arm64 must be hw-not-vulnerable, got %s", c.VulnerableClass)
	}
	c = CPUAssess("linux", "amd64", func() ([]string, error) { return nil, errNoCPUInfo }, nil)
	if c.VulnerableClass != "hw-unknown" {
		t.Fatalf("parse failure must be hw-unknown, got %s", c.VulnerableClass)
	}
}

func TestCPUAssessDarwinSysctl(t *testing.T) {
	// Uppercase machdep.cpu.features output with AVX512VBMI present.
	sysctl := func(name string) (string, error) {
		if name == "machdep.cpu.features" {
			return "FPU AVX512F AVX512BW AVX512VBMI BMI2 SSE", nil
		}
		return "", nil
	}
	c := CPUAssess("darwin", "amd64", nil, sysctl)
	if c.VulnerableClass != "hw-vulnerable" {
		t.Fatalf("want hw-vulnerable, got %s", c.VulnerableClass)
	}
	sysctl = func(name string) (string, error) {
		return "FPU AVX512F SSE", nil
	}
	c = CPUAssess("darwin", "amd64", nil, sysctl)
	if c.VulnerableClass != "hw-not-vulnerable" {
		t.Fatalf("want hw-not-vulnerable, got %s", c.VulnerableClass)
	}
}

func TestClassifyProcess(t *testing.T) {
	mit := classifyProcess("11", "", "/usr/lib/jvm/temurin-17/bin/java -XX:-UseBASE64Intrinsics -jar app.jar",
		[]string{"/usr/lib/jvm/temurin-17/bin/java", "-XX:-UseBASE64Intrinsics", "-jar", "app.jar"})
	if mit.Status != "mitigated" {
		t.Fatalf("want mitigated, got %s", mit.Status)
	}
	vuln := classifyProcess("12", "", "/usr/lib/jvm/temurin-17/bin/java -jar app.jar",
		[]string{"/usr/lib/jvm/temurin-17/bin/java", "-jar", "app.jar"})
	if vuln.Status != "vulnerable-no-mitigation" {
		t.Fatalf("want vulnerable-no-mitigation, got %s", vuln.Status)
	}
	if vuln.JVMHome != "/usr/lib/jvm/temurin-17" {
		t.Fatalf("home guess: %q", vuln.JVMHome)
	}
	unk := classifyProcess("13", "", "python server.py", []string{"python", "server.py"})
	if unk.Status != "unknown-home" {
		t.Fatalf("want unknown-home, got %s", unk.Status)
	}
	flagOpts := []string{"java", "-XX:TieredStopAtLevel=3", "-cp", "app"}
	if !HasMitigationFlags(flagOpts) {
		t.Fatal("TieredStopAtLevel=3 must count as mitigation")
	}
	if HasMitigationFlags([]string{"java", "-jar", "app"}) {
		t.Fatal("no mitigation flags expected")
	}
}

func TestRunAgainstFixtureTree(t *testing.T) {
	rep, err := Run("linux", "amd64", Options{Dirs: []string{td("jvms")}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Total < 7 {
		t.Fatalf("expected >=7 jvms, got %d", rep.Summary.Total)
	}
	if rep.Summary.Vulnerable == 0 {
		t.Fatal("fixture tree must contain vulnerable jvms")
	}
	if rep.Summary.Mystery == 0 {
		t.Fatal("broken fixture must be mystery")
	}
	if rep.CPU.Arch != "linux/amd64" {
		t.Fatalf("arch not echoed: %+v", rep.CPU)
	}
}

func TestProcessProgramTokenOnly(t *testing.T) {
	// Wrapper scripts that mention java/jdk anywhere in their arguments are
	// not JVMs; only a java-like program token is.
	for _, bad := range []string{
		"/bin/bash",
		"/opt/homebrew/bin/bash",
		"sh",
		"/Users/x/java4shell-detector",
		"python3",
	} {
		if programIsJVM(bad) {
			t.Fatalf("program token %q must not classify as JVM", bad)
		}
	}
	for _, good := range []string{
		"java",
		"/usr/bin/java",
		"/usr/lib/jvm/jdk-24.jdk/Contents/Home/bin/java",
		"C:\\opt\\java\\bin\\java.exe",
		"/opt/java/openjdk/bin/java",
	} {
		if !programIsJVM(good) {
			t.Fatalf("program token %q must classify as JVM", good)
		}
	}
	// The decision path is per-token only: a multi-token command line must
	// not classify, even when the later tokens mention jdk/java.
	if programIsJVM("bash -c 'export JDK_HOME=/usr/lib/jvm/jdk-24.jdk && ls java'") {
		t.Fatal("multi-token input must not classify (callers pass argv[0] only)")
	}
}

func TestProcessScanLinux(t *testing.T) {
	// Run is called with goos linux; /proc does not exist on macOS so
	// ScanProcesses must not blow up the report.
	rep, _ := Run("linux", "amd64", Options{Dirs: []string{td("jvms")}})
	if rep.Processes == nil {
		t.Log("process scan returned nil (no /proc on this host) - acceptable")
	}
}

// repoRoot walks up from cwd to the directory containing go.mod.
func repoRoot() string {
	wd, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return ""
		}
		wd = parent
	}
}

// td returns the path to testdata/p from the test's working directory.
func td(p string) string {
	return filepath.Join(repoRoot(), "testdata", p)
}
