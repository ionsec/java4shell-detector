# Java4Shell Hunt Guide — Others & Generic Apps

Trigger: 64×'A'+'=' (65 chars), 128×'A'+'=' on JDK17. Never send the trigger at production
stacks (Spring Security/Tomcat on Temurin 17.0.21+9 dies pre-auth, exit 134).

## Where it runs
- **Kafka Broker** (:9092) — speaks its own binary protocol, NO HTTP surface; Java4Shell reaches
  it via authenticated produce/fetch payloads inside protocol frames (post-auth RCE, Calif).
- **Gerrit** (:8080 HTTP/UI, :29418 SSH) — HTTP Basic/Bearer auth + Jetty (post-auth RCE).
- **Spinnaker** (Deck UI + Gate/Orca/Clouddriver services, typically :9000 Gate) — REST APIs,
  auth tokens (post-auth RCE).
- **PingFederate** (:9031 HTTPS) — SAML/OIDC, SAML/OAuth assertions via Base64 (pre-auth RCE).
- **Generic Spring Boot / Struts / Tomcat** — any app decoding user-supplied Base64 via
  `Base64.getDecoder()/getUrlDecoder()` on an affected JDK (auth headers, JWT parts, file
  uploads, websockets, DB/driver payloads).

## Decoder routes (exact endpoints/fields feeding Base64)
- Kafka: SASL/SSL `PLAIN`/`SCRAM` initial handshake carries base64 auth data inside protocol frames.
- Gerrit: `/a/*` REST endpoints with `Authorization: Basic`; SSH auth via key exchange.
- Spinnaker: Gate `/auth/*` endpoints, service-account tokens.
- PingFederate: SAML Request/Response, OAuth tokens, WS-Federation pass-through — all base64-wrapped.
- Generic: every `Authorization: Basic/Bearer/JWT` header; multipart bodies with base64-decoded
  attachments; request bodies fed into `Base64.getDecoder()` (lab-verified RCE route per Hadrian).

## What to grep (exact commands)
```bash
# Linux (any of the above)
grep -rniE 'IllegalArgumentException' /var/log/<product>/*.log | grep -iE 'base64|decode'
grep -hoE 'A{64}=|A{128}=' /var/log/<product>/access*.log 2>/dev/null
find /opt/<product> /var/log/<product> /tmp -name 'hs_err_pid*.log' -newermt '-7 days'
# container
docker exec <container> java -version 2>&1
docker exec <container> cat /opt/java/openjdk/release 2>/dev/null | grep -E 'JAVA_VERSION|IMPLEMENTOR'
# macOS
find /usr/local -name 'hs_err_pid*.log' 2>/dev/null
grep -rniE 'IllegalArgument' ~/kafka/logs/server.log
# Windows
findstr /S /R /I "hs_err_pid" "%PRODUCT_HOME%\<product>\logs\hs_err_pid*.log"
findstr /R /I "IllegalArgumentException" "%PRODUCT_HOME%\%product%\logs\*"
```
- IAE-burst regex, per client_ip (Splunk/elastic/sentinel-side, siem/ files): 20+ IllegalArgumentException
  in a 5-min window from one IP on a Base64 decode path = trigger probing.

## JVM version + flag verification
```bash
# Linux
ps -ef | grep '[j]ava' | grep -oE '\-XX:[^ ]*'   # should include -XX:-UseBASE64Intrinsics
jcmd <pid> VM.version                            # live JVM
# macOS
/usr/libexec/java_home -V; java -version 2>&1
# Windows
wmic process where "name='java.exe'" get CommandLine,ProcessId
# Container
docker exec <container> bash -c 'cat $(dirname $(which java))/release | grep JAVA_VERSION'
```
Vulnerable = OpenJDK 17.0.6+ / 21.x / 25.x / 27.x, no 4th version segment (bare "17.0.21" = vulnerable;
"17.0.21.1+4" fixed).

## Patch-check per vendor
- Corretto: 17.0.21.1.2+ | Oracle: 17.0.21.1+4 | Temurin (Adoptium): fixed build PENDING (17.0.21+9 vulnerable).
- Rebuild container images — host-side patch does NOT reach a container's bundled JDK.
- Interim flags: `-XX:-UseBASE64Intrinsics` (recommended), `-XX:UseAVX=2` (x86-64 ONLY — JVM fails to
  start on ARM), `-XX:+UnlockDiagnosticVMOptions -XX:DisableIntrinsic=_base64_decodeBlock` (diagnostic flag: without the unlock option the JVM refuses to start), `-Xint`, `-XX:TieredStopAtLevel=<4`.

## Post-exploit follow-up
- hs_err logs under `/tmp`, `<product>/logs`, or the JVM working dir. Check fatal-error frames for
  Base64/AVX stub symbols; container exit code 134/139 (SIGABRT/SEGV class) is the crash signature.
- Process tree: JVM spawning shells/interpreters (sigma spawn rules; kafka/gerrit/spinnaker all covered
  by ParentImage=java).
- Anomalous outbound TLS from the JVM service identity — samczsun client-side vector: a JVM that
  opens a TLS connection to a malicious/compromised server can be exploited with NO exposed
  service. Baseline each Java service's egress allowlist and alert on new destinations.
- JavaBleed-style mass reads: heap-disclosure shows up as oversized responses with non-ASCII bytes
  where valid JSON/binary content was expected.
- HTTP Basic pre-auth crash (verified Spring Security 6.2.8 / Tomcat 10.1.62 on Temurin 17.0.21+9):
  exit 134 + hs_err_pid log written but process dies BEFORE login; correlate the crash timestamp with
  the upstream proxy access log for the 64×'A'+'=' request.
- JIT warm-up caveat: a single first request to a cold JVM misses the intrinsic — low-volume or
  freshly-restarted services may show ZERO network/log signals; rely on host-side inventory.
  No universal exploit exists: absence of observed exploitation is not proof of safety.
