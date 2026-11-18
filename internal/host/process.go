package host

import (
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Mitigation flags recognized on java command lines.
var mitigationFlags = []string{
	"-xx:-usebase64intrinsics",
	"-xx:useavx=2",
	"-xx:disableintrinsic=_base64_decodeblock",
	"-xint",
	"-xx:tieredstopatlevel=1",
	"-xx:tieredstopatlevel=2",
	"-xx:tieredstopatlevel=3",
}

// ScanProcesses finds running JVM processes. Injectable via goos.
func ScanProcesses(goos string) ([]Process, error) {
	switch goos {
	case "linux":
		return scanLinuxProcs()
	case "darwin":
		return scanDarwinProcs()
	case "windows":
		return scanWindowsProcs()
	}
	return nil, nil
}

func scanLinuxProcs() ([]Process, error) {
	var out []Process
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		n := e.Name()
		if !isAllDigits(n) {
			continue
		}
		pid, _ := strconv.Atoi(n)
		data, err := os.ReadFile("/proc/" + n + "/cmdline")
		if err != nil || len(data) == 0 {
			continue
		}
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		args := splitCmdline(data)
		if len(args) == 0 {
			continue
		}
		// Decide on the program token (argv[0]) only — a wrapper script
		// whose text merely mentions "jdk"/"java" is not a JVM.
		if !strings.Contains(cmdline, "java") || !programIsJVM(args[0]) {
			continue
		}
		out = append(out, classifyProcess(strconv.Itoa(pid), "", cmdline, args))
		pids = append(pids, pid)
	}
	sort.Slice(out, func(i, j int) bool { return pidOf(out[i]) < pidOf(out[j]) })
	return out, nil
}

func pidOf(p Process) int { n, _ := strconv.Atoi(p.PID); return n }

func splitCmdline(data []byte) []string {
	parts := strings.Split(string(data), "\x00")
	var args []string
	for _, p := range parts {
		if p != "" {
			args = append(args, p)
		}
	}
	return args
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func scanDarwinProcs() ([]Process, error) {
	raw, err := execCommand("ps", "-axo", "pid=,user=,command=")
	if err != nil {
		return nil, err
	}
	var out []Process
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, " ", 3)
		if len(fields) < 3 {
			continue
		}
		pid, user, cmd := strings.TrimSpace(fields[0]), strings.TrimSpace(fields[1]), fields[2]
		prog := strings.Fields(cmd)
		if len(prog) == 0 {
			continue
		}
		// Program token decides (see scanLinuxProcs note above).
		if !strings.Contains(cmd, "java") || !programIsJVM(prog[0]) {
			continue
		}
		out = append(out, classifyProcess(pid, user, cmd, prog))
	}
	return out, nil
}

func scanWindowsProcs() ([]Process, error) {
	var out []Process
	csv, err := execCommand("tasklist", "/FI", "IMAGENAME eq java.exe", "/FO", "CSV", "/NH")
	if err != nil || csv == "" {
		// tool absence is a documented limitation
		return nil, nil
	}
	for _, line := range strings.Split(csv, "\n") {
		f := strings.Split(strings.TrimSpace(line), `","`)
		if len(f) < 2 || !strings.Contains(line, "java") {
			continue
		}
		pid := strings.Trim(strings.TrimSpace(f[1]), `"`)
		out = append(out, classifyProcess(pid, "", "java.exe", nil))
	}
	// Try to enrich with wmic command lines.
	if wm, err := execCommand("wmic", "process", "where", "name='java.exe'", "get", "ProcessId,CommandLine", "/FORMAT:CSV"); err == nil {
		for _, line := range strings.Split(wm, "\n") {
			if !strings.Contains(line, "java") {
				continue
			}
			parts := strings.Split(strings.TrimSpace(line), ",")
			if len(parts) >= 3 {
				cmd, pid := parts[len(parts)-2], strings.TrimSpace(parts[len(parts)-1])
				for i := range out {
					if out[i].PID == pid {
						out[i].CmdlineSnippet = cmd
						out[i] = classifyProcess(pid, out[i].User, cmd, strings.Fields(cmd))
					}
				}
			}
		}
	}
	return out, nil
}

// looksLikeJava filters the loose "contains java" prefilter down to actual
// JVM executables (avoids matching e.g. java4shell-detector itself).
func looksLikeJava(loweredCmdline string) bool {
	if isJVMCommand(loweredCmdline) {
		return true
	}
	// Match ".../bin/java" or ".../jre/bin/java" style paths.
	for _, tok := range strings.Fields(loweredCmdline) {
		if strings.HasSuffix(tok, "/bin/java") || strings.HasSuffix(tok, `\bin\java`) {
			return true
		}
	}
	return false
}

// classifyProcess determines mitigation status from the command line.
func classifyProcess(pid, user, cmdline string, args []string) Process {
	p := Process{PID: pid, User: user, CmdlineSnippet: truncate(cmdline, 300)}
	lowered := strings.ToLower(cmdline)
	if len(args) == 0 {
		p.Status = "unknown-home"
		return p
	}
	mitigated := false
	for _, flag := range strings.Split(lowered, " ") {
		for _, m := range mitigationFlags {
			if flag == m {
				mitigated = true
			}
		}
	}
	_ = args
	if isJVMCommand(lowered) {
		p.JVMHome = GuessHomeFromCmdline(args)
		if mitigated {
			p.Status = "mitigated"
		} else {
			p.Status = "vulnerable-no-mitigation"
		}
	} else {
		p.Status = "unknown-home"
	}
	return p
}

var jvmRe = regexp.MustCompile(`(^|/)javaw?(\.exe)?$`)

// programIsJVM decides solely from the program token (argv[0]): true for a
// java/javaw binary path, false for anything else (shells, wrappers, tools
// whose arguments merely mention java/jdk). Backslashes are normalized so
// Windows-style paths match. This is deliberately NOT a substring search —
// a token like "jdk-wrapper.sh" is not a JVM.
func programIsJVM(prog string) bool {
	p := strings.ToLower(strings.ReplaceAll(prog, "\\", "/"))
	p = strings.Trim(p, `"'`)
	return jvmRe.MatchString(p)
}

func isJVMCommand(loweredCmdline string) bool {
	for _, tok := range strings.Fields(loweredCmdline) {
		if strings.Contains(tok, "jre") || strings.Contains(tok, "jdk") ||
			jvmRe.MatchString(tok) || strings.HasSuffix(tok, "/java") || strings.HasSuffix(tok, `\java`) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func execCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// HasMitigationFlags reports whether the args disable the vulnerable intrinsic path.
func HasMitigationFlags(args []string) bool {
	for _, a := range args {
		l := strings.ToLower(a)
		for _, m := range mitigationFlags {
			if l == m {
				return true
			}
		}
	}
	return false
}

// GuessHomeFromCmdline tries to locate a JDK home inside a java command line.
func GuessHomeFromCmdline(args []string) string {
	for _, a := range args {
		if jvmRe.MatchString(strings.ToLower(a)) {
			// home is likely 3 levels up (bin/java)
			parts := strings.Split(a, "/")
			if runtime.GOOS == "windows" {
				return ""
			}
			if len(parts) >= 3 {
				return strings.Join(parts[:len(parts)-2], "/")
			}
		}
	}
	return ""
}
