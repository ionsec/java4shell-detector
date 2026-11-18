# Java4Shell Hunt Guide — JFrog Artifactory

Trigger: 64×'A'+'=' (65 chars), 128×'A'+'=' on JDK 17-class runtimes. Never send the
trigger at production stacks (Spring Security/Tomcat on Temurin 17.0.21+9 dies pre-auth).

## Where it runs
- Artifactory JVM (Tomcat bundle), :8081/:8082 (Tomcat HTTP/AJP and artifactory context), with
  Access (auth) service. Pre-auth RCE demonstrated by Calif on default config.

## Decoder routes (exact endpoints/fields feeding Base64)
- HTTP Basic auth on all REST/download/upload endpoints — the `Authorization: Basic <b64>`
  credential decodes via `java.util.Base64` in the Access auth chain pre-auth.
- API key / Bearer token headers (`X-JFrog-Art-Api`, `Authorization: Bearer`).
- Maven/Gradle/Conan/Helm deploy payloads (base64-wrapped metadata, PGP-signed poms).
- CI/proxy integration payloads (Jenkins/BuildInfo JSON bodies with base64 fields).
- Artifactory SAML/OAuth plugin exchanges.

## What to grep (exact commands)
```bash
# Linux / container
docker exec artifactory cat /opt/jfrog/artifactory/var/work/../*.release 2>/dev/null || \
docker exec artifactory java -version 2>&1
grep -rniE 'IllegalArgumentException' /var/opt/jfrog/artifactory/log/artifactory*.log 2>/dev/null \
  | grep -iE 'base64|decode'
find /var/opt/jfrog/artifactory/log /opt/jfrog/artifactory/var/log -name 'hs_err_pid*.log' \
  -newermt '-7 days'
```
```bash
# macOS
find ~/artifactory-oss-pro*/artifactory/tomcat/logs -name 'hs_err_pid*.log' 2>/dev/null
grep -rniE 'IllegalArgument' ~/artifactory-oss-pro*/artifactory/tomcat/logs/*.log
```
```bash
# Windows (bundled Tomcat)
findstr /S /R /I "hs_err_pid" "C:\jfrog\artifactory-oss\var\log\hs_err_pid*.log"
findstr /R /I "IllegalArgumentException" "C:\jfrog\artifactory-oss\var\log\artifactory-service.log"
```

## JVM version + flag verification
```bash
docker exec artifactory java -version 2>&1
docker exec artifactory bash -c 'cat /opt/jfrog/artifactory/app/artifactory/tomcat/bin/../*.version 2>/dev/null || java -XX:+PrintFlagsFinal -version 2>&1 | head -3'
ps -ef | grep '[c]atalina' | grep -oE '\-XX:[^ ]*'
```
Vulnerable = OpenJDK 17.0.6+ / 21.x / 25.x / 27.x without the fix segment (bare "17.0.21" = vulnerable).

## Patch-check per vendor
- JFrog ships Artifactory with a bundled JDK — upgrade to a release on the FIXED JVM build
  (Corretto 17.0.21.1.2+ / Oracle 17.0.21.1+4; Temurin fixed build pending at disclosure).
- Image rebuild required for containers (host patch does not reach the container's JRE).
- Interim: `-XX:-UseBASE64Intrinsics` in `ARTIFACTORY_JAVA_OPTIONS` / `jvm.options` — x86-64 only
  for `UseAVX=2`; JVM fails to start on ARM with that flag.

## Post-exploit follow-up
- hs_err logs under Tomcat logs / JVM workdir; exit 134/139 signals.
- Artifactory audit log: unexpected repo permissions, new users/tokens, plugin/scripting REST calls.
- Process tree: JVM spawning shells (sigma spawn rules).
- Anomalous outbound TLS from Artifactory JVM identity toward remote repos/bintray-style
  mirrors — baseline its remote-repo allowlist (samczsun client-side vector).
- JavaBleed: heap leaks in binary download responses (unexpected non-artifact bytes in downloads).
