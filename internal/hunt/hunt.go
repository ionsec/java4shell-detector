// Package hunt scans the filesystem for hs_err JVM crash logs and flags
// potential Java4Shell (CVE-2026-114938) trigger crashes.
package hunt

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Finding is one analyzed crash log.
type Finding struct {
	Path         string `json:"path"`
	Timestamp    string `json:"timestamp"`
	Signal       string `json:"signal"`
	Base64Frames bool   `json:"base64_frames"`
	JavaHome     string `json:"java_home"`
	Excerpt      string `json:"excerpt"`
}

// Report is the stable hunt-mode JSON schema.
type Report struct {
	RootsScanned []string  `json:"roots_scanned"`
	Files        []Finding `json:"files"`
	Summary      struct {
		FilesFound      int `json:"files_found"`
		PossibleJ4Shell int `json:"possible_java4shell"`
	} `json:"summary"`
	AssessmentNote string `json:"assessment_note"`
}

// Options: roots to scan and max file size in MB.
type Options struct {
	Roots     []string
	MaxSizeMB int64
}

var signalRe = regexp.MustCompile(`(?i)(EXCEPTION_ACCESS_VIOLATION|SIGSEGV|SIGABRT|exited abnormally|Internal Exceptions)`)

var base64FrameRe = regexp.MustCompile(`(?i)(_base64_decodeBlock|java\.util\.Base64|Base64\$Decoder|AbstractAssembler)`)

var timestampRe = regexp.MustCompile(`^(#\d+)? ?(?:An unexpected error|.*Time: .*)`)

var tsRe = regexp.MustCompile(`Time: .*`)

var javaHomeRe = regexp.MustCompile(`(?m)^[#\s]*(?:Command line|java_command):\s*(\S+)`)

// Run walks the roots for hs_err logs, reads and classifies each.
func Run(opts Options) Report {
	if opts.MaxSizeMB <= 0 {
		opts.MaxSizeMB = 50
	}
	if len(opts.Roots) == 0 {
		cwd, _ := os.Getwd()
		opts.Roots = []string{cwd}
	}
	rep := Report{RootsScanned: opts.Roots}
	for _, root := range opts.Roots {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			name := d.Name()
			if !d.IsDir() && isHsErr(name) {
				rep.Summary.FilesFound++
				f := analyze(path, opts.MaxSizeMB<<20)
				if f != nil {
					rep.Files = append(rep.Files, *f)
					rep.Summary.PossibleJ4Shell++
				}
			}
			return nil
		})
	}
	rep.AssessmentNote = "findings are potential Java4Shell trigger crashes (fatal JVM error with Base64 decode frames); correlate timestamps with malformed-Base64 request bursts then patch to a fixed build or apply -XX:-UseBASE64Intrinsics (see README)."
	return rep
}

func isHsErr(name string) bool {
	ln := strings.ToLower(name)
	return strings.HasPrefix(ln, "hs_err") && (strings.HasSuffix(ln, ".log") || !strings.Contains(ln, "."))
}

// analyze reads one hs_err log and decides whether it looks like a
// Java4Shell intrinsic crash.
func analyze(path string, maxSize int64) *Finding {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > maxSize {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := string(data)
	if !signalRe.MatchString(text) {
		return nil
	}
	if !base64FrameRe.MatchString(text) {
		return nil
	}
	f := &Finding{Path: path, Signal: firstMatch(signalRe, text), Base64Frames: true}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "Time:") {
			f.Timestamp = strings.TrimSpace(line)
			break
		}
	}
	if m := tsRe.FindString(text); f.Timestamp == "" {
		f.Timestamp = strings.TrimSpace(m)
	}
	if m := javaHomeRe.FindStringSubmatch(text); m != nil {
		cand := strings.TrimSpace(m[1])
		// Accept only a plausible java binary path from the hs_err command
		// line — never a fragment of a stack frame.
		if strings.HasSuffix(cand, "/java") || strings.HasSuffix(cand, "java.exe") || strings.Contains(cand, "/bin/") {
			f.JavaHome = cand
		}
	}
	f.Excerpt = excerptAround(text, base64FrameRe, 6)
	return f
}

func firstMatch(re *regexp.Regexp, text string) string {
	if m := re.FindString(text); m != "" {
		return m
	}
	return "signal detected"
}

// excerptAround returns lines around the first Base64 frame hit, extended
// far enough to include Java stack frames (lines starting with "j ").
func excerptAround(text string, re *regexp.Regexp, linesAround int) string {
	lines := strings.Split(text, "\n")
	hit := -1
	for i, l := range lines {
		if re.MatchString(l) {
			hit = i
			break
		}
	}
	if hit < 0 {
		return ""
	}
	start := hit - 1
	if start < 0 {
		start = 0
	}
	end := hit + linesAround
	if end > len(lines) {
		end = len(lines)
	}
	// Walk forward while a Java stack frame section has not started yet.
	for i := hit; i < end+8 && i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "j ") || strings.HasPrefix(strings.TrimSpace(lines[i]), "Java frames:") {
			end = i + linesAround
			if end > len(lines) {
				end = len(lines)
			}
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}
