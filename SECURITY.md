# SECURITY.md — java4shell-detector

This is a **read-only inventory tool**. It is designed not to cause harm:

- **Never sends the CVE-2026-114938 trigger** (`'A'*64+'='` /
  `'A'*128+'='`). The trigger crashes vulnerable JVMs (verified exit 134,
  hadrian.io). Network payloads are limited to HTTP `GET /` plus well-known
  health/ping paths and a Kafka ApiVersions v0 request. The constraint is
  hard-coded in `internal/net/net.go`.
- `host` and `hunt` modes write nothing outside the optional `--out` file.
- No exec by default. The only executed commands are: `java -version`
  (only with `--probe-java-version`), `sysctl` (macOS CPU flags), `ps`
  (macOS process list), `tasklist`/`wmic` (Windows process list). TLS
  verification can be skipped with `--insecure-tls` (default true) because
  the tool fingerprints services, not identities.
- Text and CSV output is stripped of terminal control characters, and CSV
  cells that begin with a formula character are neutralised, because
  banners, page titles, command lines and crash logs are attacker-influenced
  input.

## Known limitations

- Blind to containers (warning only), TLS-encrypted payloads, JIT warm-up
  windows, double-encoded triggers, and JVMs without a `release` file
  (reported `mystery`).
- Version verdicts are comparisons, not exploitability proofs. A
  `vulnerable` finding means "version within affected range"; the intrinsic
  only becomes reachable after C2 JIT compilation and on CPUs with
  avx512f+avx512bw+avx512vbmi+bmi2.
- The `net` mode fingerprints services; a product match does not prove the
  underlying JDK is vulnerable. Correlate with `host`/`hunt` and CMDB data.

## Reporting

Report security issues privately to office@ionsec.io, or through GitHub's
private vulnerability reporting on this repository. Ordinary bugs go in the
issue tracker. Do not include live credentials or customer data in reports.
