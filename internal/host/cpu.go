package host

import (
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/sys/cpu"
)

// Required CPU features for the AVX-512 Base64 intrinsic path.
var requiredFlags = []string{"avx512f", "avx512bw", "avx512vbmi", "bmi2"}

// CPUAssess computes the hardware verdict. cpuinfoFlags/sysctlFn are
// injectable for tests (pass nil to use the real system source).
func CPUAssess(goos, goarch string, cpuinfoFlags func() ([]string, error), sysctlFn func(name string) (string, error)) CPU {
	c := CPU{Arch: goos + "/" + goarch, Flags: nil, VulnerableClass: "hw-unknown"}
	switch {
	case goarch == "arm64":
		c.VulnerableClass = "hw-not-vulnerable"
		return c
	case goarch != "amd64" && goarch != "x86_64":
		c.VulnerableClass = "hw-unknown"
		return c
	}
	var present map[string]bool
	// liveSource is true when the flags come from this machine rather than
	// an injected source; only then may the running CPU's feature bits
	// (x/sys/cpu) be merged in.
	liveSource := false
	switch goos {
	case "linux":
		if cpuinfoFlags == nil {
			cpuinfoFlags = procCPUFlags
		}
		flags, err := cpuinfoFlags()
		if err != nil {
			c.VulnerableClass = "hw-unknown"
			return c
		}
		present = toSet(lowerAll(flags))
	case "darwin":
		if sysctlFn == nil {
			sysctlFn = darwinSysctl
			liveSource = true
		}
		// machdep.cpu.features: uppercase, space-separated.
		out, err := sysctlFn("machdep.cpu.features")
		if err != nil {
			c.VulnerableClass = "hw-unknown"
			return c
		}
		present = toSet(lowerAll(strings.Fields(out)))
		// AVX512VBMI and BMI2 may only appear in leaf7 bits (hex bitmask),
		// so fall through to the x/sys/cpu feature table (same CPU).
		if liveSource {
			for _, f := range x86CPUFeatures() {
				present[f] = true
			}
		}
	case "windows":
		present = toSet(x86CPUFeatures())
	default:
		c.VulnerableClass = "hw-unknown"
		return c
	}
	var found []string
	all := true
	for _, f := range requiredFlags {
		if present[f] {
			found = append(found, f)
		} else {
			all = false
		}
	}
	c.Flags = found
	// BMI2 is not always listed on darwin leaf7 output; require the three
	// AVX-512 flags plus bmi2 where the source exposes it.
	if all {
		c.VulnerableClass = "hw-vulnerable"
	} else if avx512All(present) {
		// AVX-512 trio present but bmi2 unconfirmed by this source.
		if goos == "darwin" && liveSource && cpu.X86.HasBMI2 {
			c.VulnerableClass = "hw-vulnerable"
		} else {
			c.VulnerableClass = "hw-unknown"
		}
	} else {
		c.VulnerableClass = "hw-not-vulnerable"
	}
	return c
}

func avx512All(present map[string]bool) bool {
	return present["avx512f"] && present["avx512bw"] && present["avx512vbmi"]
}

// x86CPUFeatures reads the CPU feature bits via golang.org/x/sys/cpu
// (no exec, works on windows without CPUID assembly).
func x86CPUFeatures() []string {
	var out []string
	if cpu.X86.HasAVX512F {
		out = append(out, "avx512f")
	}
	if cpu.X86.HasAVX512BW {
		out = append(out, "avx512bw")
	}
	if cpu.X86.HasAVX512VBMI {
		out = append(out, "avx512vbmi")
	}
	if cpu.X86.HasBMI2 {
		out = append(out, "bmi2")
	}
	return out
}

func toSet(flags []string) map[string]bool {
	m := map[string]bool{}
	for _, f := range flags {
		m[f] = true
	}
	return m
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return out
}

// procCPUFlags parses the flags line of the FIRST processor in /proc/cpuinfo.
func procCPUFlags() ([]string, error) {
	data, err := readFile("/proc/cpuinfo")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "flags") || strings.HasPrefix(line, "Features") {
			if i := strings.Index(line, ":"); i >= 0 {
				return strings.Fields(line[i+1:]), nil
			}
		}
	}
	return nil, errNoCPUInfo
}

var errNoCPUInfo = errStatic("no cpuinfo flags line")

type errStatic string

func (e errStatic) Error() string { return string(e) }

func darwinSysctl(name string) (string, error) {
	out, err := exec.Command("sysctl", "-n", name).Output()
	return strings.TrimSpace(string(out)), err
}

// HostInfo collects basic host identity for the report.
func HostInfo() map[string]string {
	return map[string]string{
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"goos_report": runtime.Version(),
	}
}

// ContainerHint reports whether container indicators exist on a linux host.
func ContainerHint() (bool, string) {
	if runtime.GOOS != "linux" {
		return false, ""
	}
	if fileExists("/.dockerenv") {
		return true, "containers on this host were not inventoried (/.dockerenv present)"
	}
	if data, err := readFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") || strings.Contains(s, "kubepods") {
			return true, "containers on this host were not inventoried (/proc/1/cgroup shows a container runtime)"
		}
	}
	return false, ""
}
