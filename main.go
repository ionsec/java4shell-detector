// java4shell-detector: AGPL-3.0 read-only detector for CVE-2026-114938
// (Java4Shell: x86-64 AVX-512 Base64 intrinsic OOB write in OpenJDK HotSpot).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/ionsec/java4shell-detector/internal/brand"
	"github.com/ionsec/java4shell-detector/internal/host"
	"github.com/ionsec/java4shell-detector/internal/hunt"
	"github.com/ionsec/java4shell-detector/internal/net"
)

const versionConst = "1.0.0"

const usageText = `java4shell-detector ` + versionConst + ` - detector for CVE-2026-114938 (Java4Shell)

Usage: java4shell-detector <mode> [args] [flags]

Modes:
  host      JVM inventory + CPU assessment on this machine
  net       inventory-only network scanner (never sends the CVE trigger)
  hunt      scan filesystem for hs_err JVM crash logs
  version   print version

Global flags:
  --format text|json|csv   output format (default text)
  --out <file>             write output to file instead of stdout
  --verbose                verbose output
  --quiet                  errors only
  --no-color               accepted; output is always plain text
  --accept-eula            accept the open-source license terms non-interactively
  --show-eula              print the full license/acceptance text and exit

License: AGPL-3.0. The first run requires acceptance (persisted per-user;
CI: IONSEC_EULA_ACCEPT=1); "version" and --show-eula work without it.

host flags:
  --probe-java-version     run java -version for homes missing a release file

net flags:
  --targets <host|cidr|comma-list>
  --ports <preset|custom-list>   quick | java | e.g. 80,443
  --concurrency N                default 128
  --timeout-ms N                 default 800
  --insecure-tls                 default true
  --max-hosts N                  cap expanded targets
  --kafka-probe                  default true (ApiVersions ping on 9092 only)

hunt flags:
  --root <dir>                   repeatable, default cwd
  --max-size-mb N                default 50

Exit codes: 0 = no vulnerable findings; 1 = vulnerable/exposure findings; 2 = invocation error.
`

type globalCfg struct {
	format     string
	out        string
	verbose    bool
	quiet      bool
	noColor    bool
	acceptEULA bool
	showEULA   bool
}

type netOpts = net.Options

// runMode dispatches a mode; returns (output, exitCode, err).
func runMode(args []string, g globalCfg) (string, int, error) {
	if len(args) == 0 {
		return usageText, 2, nil
	}
	mode := args[0]
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	// Global flags were already stripped by main; declare none here.

	switch mode {
	case "version":
		return brand.Lockup(), 0, nil
	case "host":
		probe := fs.Bool("probe-java-version", false, "probe java -version")
		if err := fs.Parse(restArgs(args[1:])); err != nil {
			return "", 2, err
		}
		return cmdHost(g, *probe)
	case "net":
		targets := fs.String("targets", "", "host|cidr|comma-list")
		ports := fs.String("ports", "quick", "preset or comma list")
		conc := fs.Int("concurrency", 128, "workers")
		tmo := fs.Int("timeout-ms", 800, "timeout ms")
		insecure := fs.Bool("insecure-tls", true, "skip TLS verify")
		maxHosts := fs.Int("max-hosts", 0, "max expanded targets")
		kafka := fs.Bool("kafka-probe", true, "kafka ping on 9092")
		if err := fs.Parse(restArgs(args[1:])); err != nil {
			return "", 2, err
		}
		if *targets == "" {
			return "", 2, fmt.Errorf("net mode requires --targets")
		}
		return cmdNet(g, net.Options{
			Targets: *targets, Ports: *ports, Concurrency: *conc, TimeoutMS: *tmo,
			InsecureTLS: *insecure, MaxHosts: *maxHosts, KafkaProbe: *kafka,
		})
	case "hunt":
		maxSize := fs.Int64("max-size-mb", 50, "max file size MB")
		var roots multiFlag
		fs.Var(&roots, "root", "root dir (repeatable)")
		if err := fs.Parse(restArgs(args[1:])); err != nil {
			return "", 2, err
		}
		return cmdHunt(g, hunt.Options{Roots: []string(roots), MaxSizeMB: *maxSize})
	default:
		return usageText, 2, fmt.Errorf("unknown mode %q", mode)
	}
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// restArgs reorders args so global flags given before the mode-specific
// flags still parse (the mode itself was already removed by the caller).
func restArgs(args []string) []string { return args }

func main() {
	var g globalCfg
	var gfs flag.FlagSet
	gfs.SetOutput(os.Stderr)
	gfs.StringVar(&g.format, "format", "text", "text|json|csv")
	gfs.StringVar(&g.out, "out", "", "output file")
	gfs.BoolVar(&g.verbose, "verbose", false, "verbose")
	gfs.BoolVar(&g.quiet, "quiet", false, "quiet")
	gfs.BoolVar(&g.noColor, "no-color", false, "no color")

	// Global flags may appear anywhere in argv; strip them before choosing
	// the mode so `--format json version` works too.
	argv := restArgsStripGlobals(&g, os.Args[1:])
	if len(argv) == 0 || argv[0] == "--help" || argv[0] == "-h" || argv[0] == "help" {
		fmt.Print(usageText)
		if len(argv) == 0 {
			os.Exit(2)
		}
		os.Exit(0)
	}
	mode := argv[0]
	rest := argv[1:]

	// --show-eula works before anything else, including without a mode.
	if g.showEULA {
		fmt.Print(brand.EULAText())
		os.Exit(0)
	}

	// `version` prints the lockup and license state; it never triggers the
	// acceptance gate.
	if mode == "version" {
		fmt.Print(brand.Lockup())
		if ok, err := brand.Accepted(); err == nil && ok {
			fmt.Println("license: AGPL-3.0 accepted (EULA v" + brand.EULAVersion + ")")
		} else {
			fmt.Println("license: acceptance pending — first run will ask; read with --show-eula")
		}
		os.Exit(0)
	}

	// host/net/hunt are gated behind the open-source license acceptance.
	switch mode {
	case "host", "net", "hunt":
		interactive := false
		if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			interactive = true
		}
		if err := brand.Ensure(brand.GateOpts{
			AcceptFlag:  g.acceptEULA,
			Interactive: interactive,
			Stdin:       os.Stdin,
			Stderr:      os.Stderr,
		}); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
	}

	out, code, err := runMode(append([]string{mode}, rest...), g)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if g.format != "json" {
		out = sanitizeTerminal(out)
	}
	if err := writeOut(g.out, out); err != nil {
		fmt.Fprintln(os.Stderr, "error writing output:", err)
		os.Exit(2)
	}
	if !g.quiet {
		fmt.Print(out)
		if g.out != "" {
			fmt.Fprintln(os.Stderr, "wrote", g.out)
		}
	}
	os.Exit(code)
}

// restArgsStripGlobals consumes global flags (--format/--out/--verbose/
// --quiet/--no-color, with or without '=') from args, updates g, and
// returns the remaining mode-specific args.
func restArgsStripGlobals(g *globalCfg, args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--format" || a == "--out":
			if i+1 < len(args) {
				applyGlobal(g, a, args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--format=") || strings.HasPrefix(a, "--out="):
			applyGlobal(g, a[:strings.Index(a, "=")], a[strings.Index(a, "=")+1:])
		case a == "--verbose" || strings.HasPrefix(a, "--verbose="):
			if a == "--verbose" || strings.HasSuffix(a, "=true") {
				g.verbose = true
			}
		case a == "--quiet" || strings.HasPrefix(a, "--quiet="):
			if a == "--quiet" || strings.HasSuffix(a, "=true") {
				g.quiet = true
			}
		case a == "--no-color" || strings.HasPrefix(a, "--no-color="):
			// accepted, output is always plain text
		case a == "--accept-eula" || strings.HasPrefix(a, "--accept-eula="):
			if a == "--accept-eula" || strings.HasSuffix(a, "=true") {
				g.acceptEULA = true
			}
		case a == "--show-eula" || strings.HasPrefix(a, "--show-eula="):
			if a == "--show-eula" || strings.HasSuffix(a, "=true") {
				g.showEULA = true
			}
		default:
			out = append(out, a)
		}
	}
	return out
}

func applyGlobal(g *globalCfg, name, val string) {
	switch name {
	case "--format":
		g.format = val
	case "--out":
		g.out = val
	}
}

func writeOut(path, data string) error {
	if path == "" {
		return nil
	}
	return os.WriteFile(path, []byte(data), 0o644)
}

func cmdHost(g globalCfg, probe bool) (string, int, error) {
	rep, err := host.Run(runtime.GOOS, runtime.GOARCH, host.Options{ProbeVersion: probe})
	if err != nil {
		return "", 2, err
	}
	out, err := render(g.format, rep, renderHost)
	if err != nil {
		return "", 2, err
	}
	if rep.Summary.Vulnerable > 0 {
		return out, 1, nil
	}
	if len(rep.Processes) > 0 {
		for _, p := range rep.Processes {
			if p.Status == "vulnerable-no-mitigation" {
				return out, 1, nil
			}
		}
	}
	return out, 0, nil
}

func cmdNet(g globalCfg, opts net.Options) (string, int, error) {
	raw, err := net.Run(opts)
	if err != nil {
		return "", 2, err
	}
	// enrich with exposure assessment
	var rep netReportView
	if err := json.Unmarshal([]byte(raw), &rep); err != nil {
		return "", 2, err
	}
	rep.AssessmentNote = exposureNote(rep)
	out, _ := json.MarshalIndent(rep, "", "  ")
	formatted := string(out)
	if g.format == "text" {
		formatted = renderNetText(rep)
	} else if g.format == "csv" {
		formatted = renderNetCSV(rep)
	}
	if rep.Summary.ProductMatches > 0 {
		return formatted, 1, nil
	}
	return formatted, 0, nil
}

func cmdHunt(g globalCfg, opts hunt.Options) (string, int, error) {
	if len(opts.Roots) == 0 {
		cwd, _ := os.Getwd()
		opts.Roots = []string{cwd}
	}
	rep := hunt.Run(opts)
	out, err := render(g.format, rep, renderHunt)
	if err != nil {
		return "", 2, err
	}
	if rep.Summary.PossibleJ4Shell > 0 {
		return out, 1, nil
	}
	return out, 0, nil
}
