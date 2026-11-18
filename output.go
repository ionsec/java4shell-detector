package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ionsec/java4shell-detector/internal/brand"
	"github.com/ionsec/java4shell-detector/internal/host"
	"github.com/ionsec/java4shell-detector/internal/hunt"
)

// render dispatches format: json passthrough, csv/text via rep-specific fns.
func render(format string, rep interface{}, renderFn func(interface{}) string) (string, error) {
	switch format {
	case "", "text":
		return brand.HeaderLine() + "\n\n" + renderFn(rep), nil
	case "json":
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "csv":
		return renderCSV(rep), nil
	}
	return "", fmt.Errorf("invalid --format %q (text|json|csv)", format)
}

// renderCSV flattens host/hunt reports into rows (mode-specific header).
func renderCSV(rep interface{}) string {
	switch v := rep.(type) {
	case host.Report:
		var b strings.Builder
		b.WriteString("path,implementor,java_version,status,notes\n")
		for _, j := range v.JVMs {
			b.WriteString(csvRow(j.Path, j.Implementor, j.JavaVersion, j.Status, j.Notes))
		}
		b.WriteString("pid,user,status,cmdline_snippet\n")
		for _, p := range v.Processes {
			b.WriteString(csvRow(p.PID, p.User, p.Status, p.CmdlineSnippet))
		}
		return b.String()
	case hunt.Report:
		var b strings.Builder
		b.WriteString("path,timestamp,signal,base64_frames,java_home\n")
		for _, f := range v.Files {
			b.WriteString(csvRow(f.Path, f.Timestamp, f.Signal,
				fmt.Sprintf("%t", f.Base64Frames), f.JavaHome))
		}
		return b.String()
	}
	return ""
}

// sanitizeTerminal drops control characters (ESC, C0/C1, DEL) from text
// bound for a terminal or a CSV file. Service banners, page titles,
// process command lines and crash logs are attacker-influenced, and an
// analyst's terminal should never interpret escape sequences from them.
// Newlines and tabs are kept.
func sanitizeTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			return '?'
		}
		return r
	}, s)
}

func csvRow(cells ...string) string {
	for i, c := range cells {
		// Neutralise spreadsheet formula injection from untrusted fields.
		if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
			c = "'" + c
			cells[i] = c
		}
		if strings.ContainsAny(c, ",\"\n") {
			cells[i] = `"` + strings.ReplaceAll(c, `"`, `""`) + `"`
		}
	}
	return strings.Join(cells, ",") + "\n"
}

func renderHost(rep interface{}) string {
	r := rep.(host.Report)
	var b strings.Builder
	fmt.Fprintf(&b, "host: %s/%s  cpu: %s\n", r.HostInfo["os"], r.HostInfo["arch"], r.CPU.VulnerableClass)
	if len(r.CPU.Flags) > 0 {
		fmt.Fprintf(&b, "required flags present: %s\n", strings.Join(r.CPU.Flags, ","))
	}
	fmt.Fprintf(&b, "jvms (%d):\n", len(r.JVMs))
	for _, j := range r.JVMs {
		fmt.Fprintf(&b, "  %-9s %-28s %-16s %s\n", j.Status, j.Path, j.JavaVersion, j.Notes)
	}
	fmt.Fprintf(&b, "processes (%d):\n", len(r.Processes))
	for _, p := range r.Processes {
		fmt.Fprintf(&b, "  %-9s %-7s %s\n", p.Status, p.PID, p.CmdlineSnippet)
	}
	if r.ContainersHint {
		fmt.Fprintf(&b, "warning: %s\n", r.ContainersNote)
	}
	fmt.Fprintf(&b, "summary: total=%d vulnerable=%d fixed=%d mitigated=%d mystery=%d\n",
		r.Summary.Total, r.Summary.Vulnerable, r.Summary.Fixed, r.Summary.Mitigated, r.Summary.Mystery)
	fmt.Fprintf(&b, "assessment: %s\n", r.AssessmentNote)
	return b.String()
}

// netReportView mirrors net's JSON plus the assessment note.
type netReportView struct {
	Targets []netPortRow `json:"targets"`
	Summary struct {
		Probed         int `json:"probed"`
		Open           int `json:"open"`
		ReachedHTTP    int `json:"reached_http"`
		ProductMatches int `json:"product_matches"`
	} `json:"summary"`
	AssessmentNote string `json:"assessment_note"`
}

type netPortRow struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Product    string `json:"product"`
	Confidence string `json:"confidence,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

// califList: products Calif demonstrated vulnerable in default configurations.
var califList = map[string]string{
	"keycloak":      "pre-auth RCE in default config (Calif)",
	"jira":          "pre-auth RCE in default config (Calif)",
	"confluence":    "pre-auth RCE in default config (Calif)",
	"artifactory":   "pre-auth RCE in default config (Calif)",
	"jenkins":       "pre-auth RCE in default config (Calif)",
	"pingfederate":  "pre-auth RCE in default config (Calif)",
	"solr":          "post-auth RCE (Calif)",
	"elasticsearch": "post-auth RCE (Calif)",
	"gerrit":        "post-auth RCE (Calif)",
	"spinnaker":     "post-auth RCE (Calif)",
	"kafka broker":  "post-auth RCE (Calif)",
	"tomcat":        "exploited framework (Calif/Wiz)",
	"spring boot":   "exploited sample framework (Calif)",
}

func exposureNote(rep netReportView) string {
	hits := map[string]bool{}
	for _, t := range rep.Targets {
		if t.Product != "" {
			if _, ok := califList[t.Product]; ok {
				hits[t.Product] = true
			} else {
				hits["__other__"] = true
			}
		}
	}
	var parts []string
	for p := range califList {
		if hits[p] {
			parts = append(parts, fmt.Sprintf("%s: %s", p, califList[p]))
		}
	}
	if hits["__other__"] {
		parts = append(parts, "other fingerprinted services: exposure unknown, verify JDK version")
	}
	if len(parts) == 0 {
		return "no product matches found."
	}
	sort.Strings(parts)
	return "CVE-2026-114938 exposure note (inventory only; the trigger payload was never sent): " +
		strings.Join(parts, "; ") + "."
}

func renderNetText(rep netReportView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "net scan: probed=%d open=%d reached_http=%d product_matches=%d\n",
		rep.Summary.Probed, rep.Summary.Open, rep.Summary.ReachedHTTP, rep.Summary.ProductMatches)
	for _, t := range rep.Targets {
		fmt.Fprintf(&b, "  %s:%d", t.IP, t.Port)
		if t.Product != "" {
			fmt.Fprintf(&b, " %s (%s) %s", t.Product, t.Confidence, t.Evidence)
		}
		if t.HTTPStatus != 0 {
			fmt.Fprintf(&b, " http_status=%d", t.HTTPStatus)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "assessment: %s\n", rep.AssessmentNote)
	return b.String()
}

func renderNetCSV(rep netReportView) string {
	var b strings.Builder
	b.WriteString("ip,port,product,confidence,evidence,http_status\n")
	for _, t := range rep.Targets {
		st := ""
		if t.HTTPStatus != 0 {
			st = fmt.Sprintf("%d", t.HTTPStatus)
		}
		b.WriteString(csvRow(t.IP, fmt.Sprintf("%d", t.Port), t.Product, t.Confidence, t.Evidence, st))
	}
	return b.String()
}

func renderHunt(rep interface{}) string {
	r := rep.(hunt.Report)
	var b strings.Builder
	fmt.Fprintf(&b, "hunt: roots=%v files_found=%d possible_java4shell=%d\n",
		r.RootsScanned, r.Summary.FilesFound, r.Summary.PossibleJ4Shell)
	for _, f := range r.Files {
		fmt.Fprintf(&b, "  %s\n    timestamp: %s\n    signal: %s\n    base64_frames: %t\n    java_home: %s\n",
			f.Path, f.Timestamp, f.Signal, f.Base64Frames, f.JavaHome)
		excerpt := f.Excerpt
		if len(excerpt) > 400 {
			excerpt = excerpt[:400] + "..."
		}
		if excerpt != "" {
			fmt.Fprintf(&b, "    excerpt: %s\n", indentOneLine(excerpt))
		}
	}
	fmt.Fprintf(&b, "assessment: %s\n", r.AssessmentNote)
	return b.String()
}

func indentOneLine(s string) string {
	return strings.ReplaceAll(s, "\n", " | ")
}
