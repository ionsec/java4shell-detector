package verdict

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		name        string
		javaVersion string
		implVersion string
		want        string
	}{
		// Version-string nuances (see README, "Version rules").
		{"temurin current at disclosure", "17.0.9", "Eclipse Temurin", StatusVulnerable},
		{"temurin vulnerable no 4th segment", "17.0.21", "Eclipse Temurin", StatusVulnerable},
		{"fixed 4-segment", "17.0.21.1", "Oracle", StatusFixed},
		{"oracle fixed with build suffix", "17.0.21.1+4", "Oracle", StatusFixed},
		{"oracle CPU-internal vulnerable", "17.0.21.0.3", "Oracle", StatusVulnerable},
		{"corretto fixed", "17.0.21.1.2", "Amazon Corretto", StatusFixed},
		{"pre-17.0.6 unaffected", "17.0.5", "", StatusNotAffected},
		{"21 below fixed", "21.0.12", "", StatusVulnerable},
		{"oracle 21 internal vulnerable", "21.0.13.0.3", "Oracle", StatusVulnerable},
		{"21 fixed", "21.0.13.1", "", StatusFixed},
		{"25 below fixed", "25.0.4", "", StatusVulnerable},
		{"25 fixed", "25.0.5.1", "", StatusFixed},
		{"27 below fixed", "27.0.0", "", StatusVulnerable},
		{"27 fixed", "27.0.1.1", "", StatusFixed},
		{"8 without b33-perf", "1.8.0_511", "Oracle", StatusNotAffected},
		{"8u511b33-perf vulnerable", "1.8.0_511", "1.8.0_511-b33-perf", StatusVulnerable},
		{"generic 8 update not affected", "1.8.0_402", "", StatusNotAffected},
		{"8 major via 1.8.0 suffix", "1.8.0_511-b33-perf", "Oracle", StatusNotAffected}, // exact match required, suffix trimmed

		{"jdk 11 not affected", "11.0.24", "", StatusNotAffected},
		{"jdk 24 EOL non-LTS carries the intrinsic", "24.0.1", "", StatusVulnerable},
		{"jdk 23 EOL non-LTS carries the intrinsic", "23.0.1", "", StatusVulnerable},
		{"graalvm underlying version", "21.0.11", "Oracle GraalVM 21.0.11", StatusVulnerable},
		{"mystery empty", "", "", StatusMystery},
		{"mystery unparseable", "banana", "", StatusMystery},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := Classify(tt.javaVersion, tt.implVersion)
			if got != tt.want {
				t.Fatalf("Classify(%q,%q) = %q, want %q", tt.javaVersion, tt.implVersion, got, tt.want)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
		err  bool
	}{
		{"17.0.21", "17.0.21.0.0", false},
		{"17.0.21.1+4", "17.0.21.1.0", false},
		{"1.8.0_511", "8.0.0.511.0", false},
		{"17.0.21.0.3", "17.0.21.0.3", false},
		{"27.", "27.0.0.0.0", false},
		{"", "", true},
		{"openjdk-x", "", true},
	}
	for _, tt := range tests {
		got, err := ParseVersion(tt.in)
		if tt.err {
			if err == nil {
				t.Fatalf("ParseVersion(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", tt.in, err)
		}
		if got.String() != tt.want {
			t.Fatalf("ParseVersion(%q) = %s, want %s", tt.in, got.String(), tt.want)
		}
	}
}
