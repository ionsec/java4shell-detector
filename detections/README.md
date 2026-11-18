# Java4Shell (CVE-2026-114938) Detection & Hunt Package

Detection content for Java4Shell: out-of-bounds write in HotSpot's x86-64 Base64
AVX-512 decoder intrinsic (`decodeBlock`). Trigger: a Base64 string ending in
`A{64}=` (65 chars) or `A{128}=` on OpenJDK 17. Corruption happens BEFORE the
JVM throws `IllegalArgumentException`, so decoder errors are a symptom, not a
block. Local CPU hardware requirement: AVX-512 VBMI + BMI2 on x86-64; ARM64
not affected.

## Quick-start (deployment order)

1. **osquery pack first** — know which hosts have vulnerable JDKs (`osquery/osquery-java4shell.conf`). This is passive; run it everywhere now.
2. **Sigma host rules** — load the `sigma/` files into your Sysmon+Winlogbeat / auditd+auditbeat / Linux Sysmon collector. Crash-artifact and process-creation rules are the highest-value local signals.
3. **SIEM analytics** — import `siem/` queries (Splunk / Elastic KQL+EQL / Sentinel / M365 Advanced Hunting). Tune index and field names to your schema.
4. **Network IDS** — deploy `ids/suricata.rules` ONLY on taps where traffic is cleartext (terminating proxy/LB, internal hops). TLS hides everything.
5. **Hunt guides** — per-product deep hunts in `hunt-guides/` for Jenkins, Jira/Confluence, Keycloak, Elasticsearch, Solr, Artifactory, and generic apps.

## Rule table

| Rule file | Surface | What it catches | False-positive policy | Severity |
|---|---|---|---|---|
| sigma/lin_java_spawn_shell.yml | Linux process_creation | java/sh-java parent spawning shells/interpreters/wget+sh pipes — post-RCE indicator | Dev pipelines spawning shells from Java builds are the known FP class; baseline first | high |
| sigma/win_java_spawn_shell.yml | Windows process_creation | java.exe/javaw.exe spawning cmd/powershell/wscript/cscript/certutil/rundll32/regsvr32 — post-RCE indicator | Signed installers/updaters; compare user + cmdline to baseline | high |
| sigma/win_hs_err_file_create.yml | Windows Sysmon EID 11 | Creation of `hs_err_pid*.log` — JVM fatal crash artifact, Java4Shell trigger crash signature (correlate with spawning java PID) | Legit JVM crashes (OOM/OOME hard exits) also write hs_err logs; treat as lead, not proof | high |
| sigma/lin_hs_err_file_create.yml | Linux auditd FIM file_event | `hs_err_pid*.log` created under java app dirs — same crash artifact on Linux | Same as above | high |
| sigma/win_java_without_mitigation.yml | Windows process_creation | Java processes launched from known vulnerable-JDK install paths WITHOUT any mitigation flag — exposed-workload hunt aid (informational, status test) | Broad by design: any unmitigated java from a JDK path fires. Inventory use only | informational |
| sigma/lin_java_mitigated_flag.yml | Linux process_creation | Command lines carrying `-XX:-UseBASE64Intrinsics` / `-XX:+UnlockDiagnosticVMOptions -XX:DisableIntrinsic=_base64_decodeBlock` (diagnostic flag: without the unlock option the JVM refuses to start) / `UseAVX=2` — "mitigation applied" telemetry | Pure telemetry, keep level low; useful to verify rollout coverage | informational |
| siem/splunk.spl | Splunk | 6 hunts (trigger in web logs, double-b64 constant, hs_err, spawns, IAE bursts, slow-POST groom) | See per-query comments | mixed |
| siem/elastic.kql + elastic.eql | Elastic | IAE bursts, hs_err files, java→shell sequences, body regex (dialect-limited) | See comments | mixed |
| siem/sentinel.kql + m365-adv-hunting.kql | Sentinel/M365D | DeviceProcessEvents/DeviceFileEvents + IIS/AccessLogs regex hunts | See comments | mixed |
| osquery/osquery-java4shell.conf | osquery | AVX-512 CPU flags, JDK inventory, hs_err existence, live java processes | Inventory queries, no FP concept | n/a |
| ids/suricata.rules | Suricata | Raw + single- and double-base64 trigger on cleartext HTTP (headers, URI, body) | Only fires on cleartext; see TLS caveat | high/critical |
| hunt-guides/*.md (7 files) | product handbooks | Where Base64 decodes in each product, exact greps, JDK/flag verification, patch checks, post-exploit follow-up | — | n/a |

## Key facts box

- **Trigger string:** `A`×64 + `=` (65 chars; `AAAA...A=`), and `A`×128 + `=` on JDK 17-class runtimes (higher length threshold to reach the intrinsic). Tail forms `=`, `==`, `X=`, `X==`, `XY=`, `===` are also corrupting; `A{64}=` is the canonical one to hunt.
- **Crash artifacts:** `hs_err_pid*.log` fatal-error logs; JVM exit code **134** (or 139) shortly after malformed-Base64 requests. On Temurin 17.0.21+9, Spring Security/Tomcat stacks die pre-auth with exit 134 + hs_err log.
- **Mitigation flags:** `-XX:-UseBASE64Intrinsics` (recommended), `-XX:UseAVX=2` (x86-64 only — JVM fails to start on ARM), `-XX:+UnlockDiagnosticVMOptions -XX:DisableIntrinsic=_base64_decodeBlock`, `-Xint`, `-XX:TieredStopAtLevel<4`.
- **Affected:** OpenJDK 17.0.6+, branches 17.x/21.x/25.x/27.x; fixed in 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 (note: a bare "17.0.21" is VULNERABLE, "17.0.21.1+" is fixed). Only x86-64 with avx512f+avx512bw+avx512vbmi+bmi2.
- **JIT warm-up:** the intrinsic only runs after C2 compiles the Base64 call site — a SINGLE first request to a cold JVM will NOT trigger. Detection and tests both need traffic volume.
- **No universal exploit:** per-product chains withheld; anything decoding external Base64 via `Base64.getDecoder()`/`getUrlDecoder()` on an affected JDK is in scope (Basic auth, JWT parts, bodies, websockets).

## LIMITATIONS box

- **TLS hides payloads end to end.** Network-side and SIEM web-log detections see the trigger only on plaintext hops: terminating proxy/load balancer, internal HTTP hops, or when the app itself logs request bodies/auth headers. Anything you can't decrypt is dark.
- **JIT warm-up means first-request misses.** A cold JVM won't hit the intrinsic; low-volume exploitation may produce zero network or log signals. Rely on host-side (hs_err, spawn) and inventory coverage.
- **Request-body buffering is not a general mitigation.** nginx buffering (on by default) breaks some heap-grooming profiles, but the Elasticsearch chain runs from one complete buffered request, and post-WebSocket-upgrade frames bypass buffering. Do not treat proxies with buffering as compensating controls.
- Encoder variance: apps may re-encode, chunk, or whitespace-pad the trigger; regex hunts match the literal `A{64}=` and `A{128}=` forms and their standard double-base64 constants only.
- The double-base64 constant matches only whole-value re-encoding (e.g. inside Basic credentials); split/chunked encodings evade it.

## DESTRUCTIVE PROBE WARNING

**Never send 65- or 129-char trigger payloads (`A{64}=` / `A{128}=`) to production services to "test" CVE-2026-114938.** On several stacks — Spring Security on Tomcat running Temurin 17.0.21+9 — the trigger string in an HTTP Basic header **kills the JVM before authentication** (verified: SIGABRT-class exit **134** + `hs_err_pid` fatal log). You will take the service down. For inventory and reachability, use the passive detector in this repository (JDK version, CPU flags, mitigation flags, decoder-route mapping) instead of live-firing payloads. If you must validate exploitability at all, do it in an isolated lab VM only.

## Validation status

All Sigma YAML files parse with `python3 -c 'import yaml; yaml.safe_load(open(f))'`; osquery config is JSON-embedded SQL validated structurally; Suricata rules written to the 2510000+ free SID range but **not** validated with `suricata -T` (no suricata binary on the authoring host) — run `suricata -T -c /etc/suricata/suricata.yaml -S this.rules` before deployment.
