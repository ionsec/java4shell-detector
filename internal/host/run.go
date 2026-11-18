package host

import (
	"fmt"
	"path/filepath"

	"github.com/ionsec/java4shell-detector/internal/verdict"
)

// Options for Run: probeVersion enables `java -version` exec for homes
// missing a release file.
type Options struct {
	ProbeVersion bool
	Dirs         []string // JDK parent dirs (defaults per OS when empty)
}

// Run executes host mode and returns the report.
func Run(goos, goarch string, opts Options) (Report, error) {
	dirs := opts.Dirs
	if len(dirs) == 0 {
		dirs = DiscoverDirs(goos)
	}
	// Windows registry roots are appended to the dir list as pseudo-entries.
	_ = goos
	var probe func(string) (string, bool)
	if opts.ProbeVersion {
		probe = RunJavaVersion
	}
	var jvms []JVM
	for _, home := range append(discoveryHomes(dirs, goos), registryHomes(goos)...) {
		jvms = append(jvms, LoadJVM(home, probe))
	}
	cpu := CPUAssess(goos, goarch, nil, nil)
	procs, err := ScanProcesses(goos)
	if err != nil {
		procs = nil
	}
	// Link mitigated running processes back to their home -> mitigated-runtime.
	homeIndex := map[string]int{}
	for i, j := range jvms {
		homeIndex[filepath.Clean(j.Path)] = i
	}
	for _, p := range procs {
		if p.Status != "mitigated" {
			continue
		}
		home := p.JVMHome
		if idx, ok := homeIndex[filepath.Clean(home)]; ok {
			if jvms[idx].Status == verdict.StatusVulnerable {
				jvms[idx].Status = verdict.StatusMitigated
				jvms[idx].Notes += "; running with mitigation flags (pid " + p.PID + ")"
			}
		}
	}
	hint, hintNote := ContainerHint()
	if jvms == nil {
		jvms = []JVM{} // stable JSON schema: empty list, never null
	}
	if procs == nil {
		procs = []Process{}
	}
	rep := Report{
		HostInfo:       HostInfo(),
		CPU:            cpu,
		JVMs:           jvms,
		Processes:      procs,
		ContainersHint: hint,
		ContainersNote: hintNote,
	}
	sum := Summary{Total: len(jvms)}
	for _, j := range jvms {
		switch j.Status {
		case verdict.StatusVulnerable:
			sum.Vulnerable++
		case verdict.StatusFixed, verdict.StatusNotAffected:
			sum.Fixed++
		case verdict.StatusMitigated:
			sum.Mitigated++
		default:
			sum.Mystery++
		}
	}
	for _, p := range procs {
		if p.Status == "vulnerable-no-mitigation" {
			sum.Vulnerable++
		}
	}
	rep.Summary = sum
	rep.AssessmentNote = assessmentNote(cpu, sum)
	return rep, nil
}

func assessmentNote(c CPU, s Summary) string {
	if c.VulnerableClass != "hw-vulnerable" {
		return "CPU does not meet the AVX-512 (avx512f/avx512bw/avx512vbmi/bmi2) requirement; the vulnerable intrinsic path is not reachable on this hardware class."
	}
	if s.Vulnerable > 0 {
		return fmt.Sprintf("hw-vulnerable host with %d vulnerable JVM finding(s): patch to 17.0.21.1/21.0.13.1/25.0.5.1/27.0.1.1 or apply -XX:-UseBASE64Intrinsics.", s.Vulnerable)
	}
	return "hw-vulnerable host; no vulnerable JVM inventory found (containers and remote services are not covered by host mode)."
}

// discoveryHomes wraps DiscoverHomes with darwin special-casing already inside.
func discoveryHomes(dirs []string, goos string) []string {
	if goos == "darwin" {
		var expand []string
		for _, d := range dirs {
			if hasSuffixAny(d, "JavaVirtualMachines") {
				expand = append(expand, d)
			} else {
				expand = append(expand, d)
			}
		}
		return DiscoverHomes(expand)
	}
	return DiscoverHomes(dirs)
}

func hasSuffixAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) && s[len(s)-len(sub):] == sub {
			return true
		}
	}
	return false
}
