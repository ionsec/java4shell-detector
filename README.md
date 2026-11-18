# java4shell-detector

Read-only inventory and detection tool for **CVE-2026-114938 (Java4Shell)** —
out-of-bounds write in OpenJDK HotSpot's x86-64 Base64 AVX-512 decode
intrinsic (`_base64_decodeBlock`). AGPL-3.0.

Three modes:

| Mode | What it does | Sends anything? |
|------|--------------|-----------------|
| `host` | JVM inventory (release files), CPU AVX-512 assessment, running-process mitigation check, container hint | never |
| `net`  | TCP sweep + HTTP/TLS fingerprinting of services (Jenkins, Jira, Confluence, Keycloak, Artifactory, Elasticsearch, Solr, Tomcat, Spring Boot, Gerrit, Spinnaker, PingFederate, Kafka) | HTTP `GET /`, known-path GETs, Kafka ApiVersions ping only |
| `hunt` | Filesystem scan for `hs_err` crash logs, classifies potential Java4Shell trigger crashes | never |

## Detection pack

`detections/` holds the hunt content that goes with the detector: Sigma rules,
SIEM queries (Splunk, Elastic, Microsoft Sentinel, Defender advanced hunting),
an osquery pack, Suricata rules for cleartext hops, and per-product hunt
guides. Start with [`detections/README.md`](detections/README.md).

## 1. Quick start (zero install)

Requires Go 1.27 (build with the latest patch release, 1.27.4 or newer, for
the standard-library security fixes). No CGO; dependencies are vendored.

```
CGO_ENABLED=0 go build -o java4shell-detector .
```

Prebuilt binaries are attached to the GitHub release:
`java4shell-detector-1.0.0-<os>-<arch>[.exe]` for linux/amd64, linux/arm64,
darwin/amd64, darwin/arm64, windows/amd64 and windows/arm64, with
`SHA256SUMS`. Verify the checksum before running.

```
# macOS (Apple Silicon)
./java4shell-detector-1.0.0-darwin-arm64 host
# Linux x86-64
./java4shell-detector-1.0.0-linux-amd64 host --format json
# Windows (x64 cmd)
java4shell-detector-1.0.0-windows-amd64.exe host
```

Paths accepted: anything reachable as a filesystem path (absolute or relative);
hunt roots default to the current working directory; net targets accept a
hostname, IP, CIDR block, or comma-separated list of those.

### First-run license acceptance (open source)

The tool is AGPL-3.0 free software. Before the first `host`/`net`/`hunt`
invocation it asks you to accept the license terms and shows what the tool
does and does not do. `version` and `--show-eula` work without acceptance.

```
# read the terms
./java4shell-detector-1.0.0 --show-eula
# interactive accept (TTY): prints terms, asks  Accept? [y/N]  — persists
# non-interactive accept (CI), persists:
./java4shell-detector-1.0.0-linux-amd64 --accept-eula host
# CI without persisting a file first? set the env var (accepts and persists):
IONSEC_EULA_ACCEPT=1 ./java4shell-detector-1.0.0-linux-amd64 host --format json
```

Acceptance is stored per-user, version-stamped (a future EULA version bump
re-prompts):

| OS | File |
|---|---|
| Linux / macOS | `~/.config/ionsec/java4shell-detector/eula` (or `$XDG_CONFIG_HOME`) |
| Windows | `%APPDATA%\ionsec\java4shell-detector\eula` |

Delete the file to clear the acceptance. Refused terms → exit 2, nothing runs.

## 2. Command reference

```
java4shell-detector <mode> [args] [flags]
```

| Flag | Applies to | Meaning | Default |
|------|-----------|---------|---------|
| `--format text\|json\|csv` | all | output format | `text` |
| `--out <file>` | all | write output to file (stdout result suppressed) | off |
| `--verbose` | all | verbose output | off |
| `--quiet` | all | suppress stdout (errors still on stderr) | off |
| `--no-color` | all | accepted no-op; output is always plain text | — |
| `--probe-java-version` | host | run `java -version` only for homes missing a `release` file | off |
| `--targets <host\|cidr\|comma-list>` | net | scan targets (required) | — |
| `--ports <preset\|custom-list>` | net | `quick` (443,8443,8080,8081,9000,9200,8983), `java` (superset incl. 29418, 9092, 2181...), or e.g. `80,443` | `quick` |
| `--concurrency N` | net | worker pool size | 128 |
| `--timeout-ms N` | net | TCP connect timeout | 800 |
| `--insecure-tls` | net | skip TLS cert verification | true |
| `--max-hosts N` | net | cap on expanded targets | unlimited |
| `--kafka-probe` | net | Kafka ApiVersions v0 ping on open 9092 | true |
| `--root <dir>` | hunt | directory to scan (repeatable) | cwd |
| `--max-size-mb N` | hunt | max hs_err file size to read | 50 |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | no vulnerable / exposure findings |
| 1 | vulnerable JVMs or unmitigated JVM processes (host), product matches (net), potential trigger crashes (hunt) |
| 2 | invocation error (bad flags, unresolvable targets, unknown mode) |

### Version classification

Numeric comparison against the fact base: majors 17/21/25/27 vulnerable below
17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 (17 requires >= 17.0.6); Oracle
CPU-internal `X.Y.Z.0.N` builds compare numerically and stay vulnerable (e.g.
17.0.21.0.3 < 17.0.21.1); `17.0.21` without a 4th segment is vulnerable;
Amazon Corretto `17.0.21.1.2` is fixed; the 8u branch is affected only in the
Oracle `8u511b33-perf` build (exact `JAVA_VERSION` `1.8.0_511` +
`IMPLEMENTOR_VERSION` containing `b33-perf`); GraalVM is judged by its
underlying `JAVA_VERSION`; anything unparseable is reported as `mystery`,
never guessed. `not_affected` is an additional status for out-of-scope majors
(e.g. 8 without b33-perf, 11, other majors). A vulnerable JVM home linked to a
running process carrying a mitigation flag is reported `mitigated-runtime`.

### CPU assessment

x86-64 requires **all** of `avx512f`, `avx512bw`, `avx512vbmi`, `bmi2`
(`/proc/cpuinfo` on Linux, `sysctl machdep.cpu.features` + the x/sys CPUID
table on macOS, the x/sys CPUID feature table on Windows). arm64 is always
`hw-not-vulnerable`. Unavailable sources yield `hw-unknown`, never a false
"safe".

## 3. Why net mode never sends the trigger

The Java4Shell trigger is a Base64 string of **64 'A' followed by '='** (128
'A' on OpenJDK 17). Sending it to a vulnerable JVM **crashes the service**
(fatal error; verified process exit 134 and `hs_err_pid` logs by hadrian.io on
Temurin 17.0.21+9 against Spring Boot 3.2.12 and Tomcat 10.1.62). This tool is
inclusionary/inventory-only and hard-codes the constraint: its only network
payloads are `GET /` (and well-known health/ping paths) and the Kafka
ApiVersions v0 request. It does not decode, fuzz, or verify exploitability —
exposure is inferred from fingerprints and stated as such in the
`assessment_note` of the output.

## 4. CI wiring example

```yaml
# .github/workflows/java4shell-audit.yml
name: java4shell-audit
on: [push, workflow_dispatch]
jobs:
  host-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: go build -o detector ./detector
      - run: ./detector host --format json --out j4s-host.json
      - uses: actions/upload-artifact@v4
        with: {name: j4s-host, path: j4s-host.json}
      - name: fail on vulnerable inventory
        run: |
          ./detector host > /dev/null || {
            echo "::error::vulnerable JVM inventory found"; exit 1; }
```

In an existing pipeline the detector's own exit codes drive the gate:
`java4shell-detector host` exits 1 when vulnerable findings exist and 2 on
invocation errors.

## 5. Sample output (actual runs)

`host` on darwin/arm64 (real machine, JDK 24 found, EULA accepted in an earlier run):

```
IONSEC java4shell-detector v1.0.0 - CVE-2026-114938 - AGPL-3.0

host: darwin/arm64  cpu: hw-not-vulnerable
jvms (1):
  vulnerable /Library/Java/JavaVirtualMachines/jdk-24.jdk/Contents/Home 24.0.1           major 24 branches from mainline after 17.0.6 (advisory: 17.0.6 or newer); EOL branch has no vendor fix — migrate to patched LTS 17.0.21.1+ / 21.0.13.1+ / 25.0.5.1+ / 27.0.1.1+
processes (0):
summary: total=1 vulnerable=1 fixed=0 mitigated=0 mystery=0
assessment: CPU does not meet the AVX-512 (avx512f/avx512bw/avx512vbmi/bmi2) requirement; the vulnerable intrinsic path is not reachable on this hardware class.
```

`hunt --root testdata/hunt` (exit 1):

```
hunt: roots=[testdata/hunt] files_found=2 possible_java4shell=1
  testdata/hunt/hs_err_pid8812.log
    timestamp: # Time: Tue Nov 18 09:41:02 2026 IST
    signal: SIGSEGV
    base64_frames: true
    java_home: 
    excerpt: # Problematic frame: | # V  [jvm.dll+0x1a2d4]  _base64_decodeBlock+0x3c | # | ... | j  java.util.Base64$Decoder.decodeBlock([B[BI)V ...
assessment: findings are potential Java4Shell trigger crashes (fatal JVM error with Base64 decode frames); correlate timestamps with malformed-Base64 request bursts then patch to a fixed build or apply -XX:-UseBASE64Intrinsics (see README).
```

`net --targets 127.0.0.1 --ports 18099,18098` against a local Jenkins-header
stub (exit 1):

```
net scan: probed=2 open=1 reached_http=1 product_matches=1
  127.0.0.1:18099 jenkins (high) X-Jenkins: 2.504.1 http_status=404
assessment: CVE-2026-114938 exposure note (inventory only; the trigger payload was never sent): jenkins: pre-auth RCE in default config (Calif).
```

## 6. Rules, false-positive policy, limits

- FP policy: a vulnerable-version verdict is only a version comparison;
  mystery homes are surfaced, never judged. Hardware must show all four CPU
  flags or the finding is downgraded to the hw-not-vulnerable/hw-unknown
  class, which the assessment note spells out.
- Non-LTS EOL branches (18-20, 22-24, ...): classified **vulnerable on
  purpose** — they branch from mainline after 17.0.6 and carry the affected
  intrinsic, and no vendor fix exists for them. The advisory's plain wording
  is "OpenJDK from version 17.0.6 or newer"; vendor lists enumerate only the
  LTS branches (17/21/25/27) because enterprises run those. Treat these
  verdicts as "migrate to a patched LTS", not as a claim a fix exists.
- Blind spots:
  - **Containers**: host mode warns when `/.dockerenv` or container runtimes
    appear in `/proc/1/cgroup` but does not inventory image JREs. Rebuild
    images; patching the host leaves the in-image JDK stale.
  - **JREs/JDKs without a release file**: reported as `mystery`; use
    `--probe-java-version` (executes `java -version`) to partially cover them.
  - **Windows without tasklist/wmic**: the process scan returns nothing
    rather than guessing; registry discovery uses `HKLM\SOFTWARE\JavaSoft\*`,
    `Eclipse Adoptium`, `Amazon Corretto`, `Azul Systems\Zulu`, `Microsoft\JDK`.
  - **TLS-encrypted network surface**: the trigger is visible only in
    cleartext hops or at terminating proxies; net mode fingerprints services
    but cannot see decoded traffic, and JIT warm-up means a freshly started
    JVM will not exhibit the crash even for a vulnerable build.
  - **Double-encoded triggers** (base64-in-base64, e.g. inside Basic
    credentials) are invisible to anything but application-layer content
    inspection, which this tool does not do.

## 7. License

AGPL-3.0 — see `LICENSE`. Security notes in `SECURITY.md`.

## Development

```
git config core.hooksPath .githooks     # once per clone
```

The pre-push hook runs `scripts/leak-guard.sh`, a gitleaks scan of the commits
being pushed (when gitleaks is installed) and `go vet` / `go test`, and blocks
the push if any of them fails. The `security` workflow repeats those checks on
every push and pull request and adds govulncheck and a Suricata load test of
the rule file. Tagging `vX.Y.Z` builds the release binaries on a clean runner
and attaches them to a draft release.
