# Java4Shell Hunt Guide — Jenkins

Trigger: 64×'A'+'=' (65 chars), 128×'A'+'=' on JDK 17-class runtimes. Never send the
trigger at production — it kills Spring Security/Tomcat stacks pre-auth (exit 134).

## Where it runs
- Jenkins controller/agent JVMs; web UI on :8080 (Winstone/Jetty), CLI over SSH port :50000, and inbound agents.
- Pre-auth RCE demonstrated by Calif on default config.

## Decoder routes (exact endpoints/fields feeding Base64)
- HTTP Basic auth on every `/jenkins/*` path: `Authorization: Basic <b64>` — the decoded
  `user:apitoken`/`user:password` passes through `java.util.Base64` (Spring Security / Jetty auth chain).
- Crumb/CLI handshake and agent protocol headers.
- CSRF crumbs and JWT-like tokens in plugin auth chains.
- Any plugin accepting uploads/config payloads via `Base64.getDecoder()`/`getUrlDecoder()`.

## What to grep (exact commands)
```bash
# Linux controller
grep -rniE 'IllegalArgument.*Base64|Base64.*Illegal' /var/log/jenkins/jenkins.log
grep -hoE 'A{64}=|A{128}=' /var/log/jenkins/controller.log 2>/dev/null
grep -rniE 'A{64}=' /var/log/jenkins/access_log* 2>/dev/null

# macOS
grep -rniE 'IllegalArgument|hs_err' ~/Library/Caches/jenkins/*.log

# Windows (findstr / PowerShell)
findstr /R /S /I "IllegalArgumentException.*Base64" "%JENKINS_HOME%\jenkins.log"
findstr /R /I "hs_err_pid" "%JENKINS_HOME%\hs_err_pid*.log"
```
- IAE-burst regex (any platform, against web access logs): `(?i)IllegalArgumentException` co-occurring with `Base64|decode`.

## JVM version + flag verification
```bash
# Linux / container
docker exec jenkins cat /opt/java/openjdk/release | grep -E 'JAVA_VERSION|IMPLEMENTOR'
# non-container: java -version 2>&1 | head -3
ps -ef | grep '[j]ava' | grep -oE '\-XX:[^ ]*'
```
```bash
# macOS
/usr/libexec/java_home -V; java -version 2>&1
# Windows
&wmic process where "name='java.exe'" get CommandLine,ProcessId
```
Vulnerable = OpenJDK 17.0.6+ (17.x/21.x/25.x/27.x) with no 4th version segment (bare "17.0.21" = vulnerable; "17.0.21.1" = fixed).

## Patch-check per vendor
- Corretto: 17.0.21.1.2+ ; Temurin (Adoptium): fixed build PENDING (17.0.21+9 still vulnerable at disclosure).
- Oracle: 17.0.21.1+4, 21.0.13.1, 25.0.5.1, 27.0.1.1 ; check `IMPLEMENTOR` in the release file.
- Jenkins LTS/weekly bundles a JRE — check the bundled JRE version (`java -version` via the controller binary), not only OS-installed JDKs.

## Post-exploit follow-up
- `find /var/lib/jenkins -name 'hs_err_pid*.log' -newermt '<last restart>'` — read for Base64/AVX frames in the fatal-error stack.
- Jenkins audit log (`/audit`, `Audit List Plugin`): unexpected job/config modifications, new admin users.
- Process tree: JVM spawning sh/bash/python/nc (see sigma rules lin_java_spawn_shell / win_java_spawn_shell).
- Anomalous outbound TLS from the controller/agents (Jenkins plugin update URLs are the legit set — everything else is a lead; covers the samczsun client-side vector).
- Jenkins remoting/agent channel anomalies in `secrets/` and agent JNLP traffic.
