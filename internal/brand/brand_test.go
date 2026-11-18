package brand

import (
	"strings"
	"testing"
)

func TestGateAcceptFlagPersists(t *testing.T) {
	dir := t.TempDir() + "/eula"
	err := Ensure(GateOpts{AcceptFlag: true, StateDir: dir, Stderr: &strings.Builder{}})
	if err != nil {
		t.Fatalf("accept flag should satisfy the gate: %v", err)
	}
	if !AcceptedOn(dir, EULAVersion) {
		t.Fatal("acceptance must persist for the same EULA version")
	}
	// Second run with nothing: already accepted on file.
	if err := Ensure(GateOpts{StateDir: dir}); err != nil {
		t.Fatalf("stored acceptance should exempt later runs: %v", err)
	}
}

func TestGateEnvAccepted(t *testing.T) {
	t.Setenv("IONSEC_EULA_ACCEPT", "1")
	dir := t.TempDir() + "/eula"
	if err := Ensure(GateOpts{StateDir: dir, Stderr: &strings.Builder{}}); err != nil {
		t.Fatalf("env acceptance should satisfy the gate: %v", err)
	}
	if !AcceptedOn(dir, EULAVersion) {
		t.Fatal("env acceptance must persist too")
	}
}

func TestGateRefusesNonInteractive(t *testing.T) {
	dir := t.TempDir() + "/eula"
	err := Ensure(GateOpts{StateDir: dir, Stderr: &strings.Builder{}})
	if err == nil {
		t.Fatal("non-interactive unaccepted run must be refused")
	}
	for _, want := range []string{"--accept-eula", "IONSEC_EULA_ACCEPT", "--show-eula"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal must explain machine-friendly options; missing %q in: %v", want, err)
		}
	}
	if _, err2 := Accepted(); err2 != nil || AcceptedOn(dir+"/unused", EULAVersion) {
		// Accepted() with default path may differ per host; only require no panic.
		_ = err2
	}
}

func TestGatePromptYes(t *testing.T) {
	dir := t.TempDir() + "/eula"
	var sb strings.Builder
	err := Ensure(GateOpts{
		StateDir: dir, Interactive: true,
		Stdin:  strings.NewReader("y\n"),
		Stderr: &sb,
	})
	if err != nil {
		t.Fatalf("interactive y should pass: %v", err)
	}
	if !AcceptedOn(dir, EULAVersion) {
		t.Fatal("prompt acceptance must persist")
	}
	if !strings.Contains(sb.String(), "Accept the license terms") {
		t.Fatal("prompt text missing")
	}
}

func TestGatePromptNo(t *testing.T) {
	dir := t.TempDir() + "/eula"
	err := Ensure(GateOpts{
		StateDir: dir, Interactive: true,
		Stdin:  strings.NewReader("n\n"),
		Stderr: &strings.Builder{},
	})
	if err == nil || !strings.Contains(err.Error(), "not accepted") {
		t.Fatalf("declined terms must refuse: %v", err)
	}
	if AcceptedOn(dir, EULAVersion) {
		t.Fatal("declined terms must not persist acceptance")
	}
}

func TestEULAVersionBumpForcesReaccept(t *testing.T) {
	dir := t.TempDir() + "/eula"
	if err := AcceptAt(dir); err != nil {
		t.Fatal(err)
	}
	if AcceptedOn(dir, "9.9") {
		t.Fatal("a newer EULA version must invalidate stored acceptance")
	}
}

func TestLockupFrameAlignment(t *testing.T) {
	lines := strings.Split(Lockup(), "\n")
	if len(lines) < 5 {
		t.Fatal("lockup too short")
	}
	var frameSeen, boxSeen int
	for _, line := range lines {
		r := []rune(line)
		if len(r) == 0 {
			continue
		}
		switch r[0] {
		case '┌', '├', '└':
			frameSeen++
			if len(r) != bannerWidth {
				t.Fatalf("frame line has %d runes, want %d: %q", len(r), bannerWidth, line)
			}
		case '|':
			boxSeen++
			if len(r) != bannerWidth || r[len(r)-1] != '|' {
				t.Fatalf("box line misaligned: %q", line)
			}
		}
	}
	if frameSeen != 3 || boxSeen != 4 {
		t.Fatalf("expected 3 frame + 4 box lines, got %d/%d", frameSeen, boxSeen)
	}
}

func TestHeaderLineShape(t *testing.T) {
	h := HeaderLine()
	if !strings.Contains(h, Vendor) || !strings.Contains(h, Version) || !strings.Contains(h, CVE) {
		t.Fatalf("header line missing identity fields: %q", h)
	}
}
