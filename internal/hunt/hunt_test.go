package hunt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHuntFixtures(t *testing.T) {
	rep := Run(Options{Roots: []string{td("hunt")}, MaxSizeMB: 50})
	if rep.Summary.FilesFound != 3 {
		t.Fatalf("expected 3 hs_err files, got %d", rep.Summary.FilesFound)
	}
	if rep.Summary.PossibleJ4Shell != 2 {
		t.Fatalf("expected 2 possible java4shell crashes, got %d", rep.Summary.PossibleJ4Shell)
	}
	var f, withCmd *Finding
	for i := range rep.Files {
		switch {
		case strings.HasSuffix(rep.Files[i].Path, "hs_err_pid8812.log"):
			f = &rep.Files[i]
		case strings.HasSuffix(rep.Files[i].Path, "hs_err_pid9001.log"):
			withCmd = &rep.Files[i]
		}
	}
	if f == nil || withCmd == nil {
		t.Fatalf("missing expected fixtures in results: %+v", rep.Files)
	}
	// Command-line-derived java_home must be a real path, never a stack-frame
	// fragment like "/Native".
	if withCmd.JavaHome != "/opt/java/openjdk/bin/java" {
		t.Fatalf("java_home from Command line: %q", withCmd.JavaHome)
	}
	if f.JavaHome != "" {
		t.Fatalf("hs_err without a Command line must not invent java_home: %q", f.JavaHome)
	}
	if !f.Base64Frames {
		t.Fatal("base64_frames must be true for base64 crash fixture")
	}
	if f.Signal != "SIGSEGV" {
		t.Fatalf("signal: %q", f.Signal)
	}
	if !strings.Contains(f.Timestamp, "Time:") {
		t.Fatalf("timestamp: %q", f.Timestamp)
	}
	if !strings.Contains(f.Excerpt, "_base64_decodeBlock") || !strings.Contains(f.Excerpt, "java.util.Base64") {
		t.Fatalf("excerpt missing base64 frames:\n%s", f.Excerpt)
	}
	if strings.Contains(string(rep.AssessmentNote), "undefined") {
		t.Fatal("bad note")
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
