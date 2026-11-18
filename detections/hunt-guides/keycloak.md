# Java4Shell Hunt Guide — Keycloak

Trigger: 64×'A'+'=' (65 chars), 128×'A'+'=' on JDK 17-class runtimes. Never send the
trigger at production stacks (Spring Security/Tomcat on Temurin 17.0.21+9 dies pre-auth).

## Where it runs
- Keycloak server JVM (Quarkus-based on 17+ with embedded server; WildFly/EAP for legacy),
  typically :8080/:8443. Pre-auth RCE demonstrated by Calif on default config.

## Decoder routes (exact endpoints/fields feeding Base64)
- OpenID Connect endpoints: `/realms/<realm>/protocol/openid-connect/token`,
  `/auth`, `/userinfo` — HTTP Basic (`Authorization: Basic <b64>` for client
  credentials) decodes pre-auth via `java.util.Base64`.
- JWT/SAML payload handling — the `header.payload` segments and `POST /token` grants.
- Admin console session cookies and `X-Forwarded-*` trust chains if behind proxies.
- Service account credentials in request bodies (JSON `client_secret` values often base64-wrapped).

## What to grep (exact commands)
```bash
# Linux / container
docker exec keycloak cat /opt/keycloak/lib/../release 2>/dev/null || docker exec keycloak cat /opt/keycloak/bin/../release
grep -rniE 'IllegalArgumentException' /opt/keycloak/logs/* /opt/keycloak/data/log/* 2>/dev/null | grep -iE 'base64|decode'
find /opt/keycloak -name 'hs_err_pid*.log' -newermt '-7 days'
# macOS
grep -rniE 'IllegalArgument' ~/keycloak-*/standalone/log/server.log
```
```bash
# Windows (native or S2I)
findstr /S /R /I "hs_err_pid" "%KEYCLOAK_HOME%\logs\hs_err_pid*.log"
findstr /R /I "IllegalArgumentException" "%KEYCLOAK_HOME%\standalone\log\server.log"
```
- Access-log IAE burst: same regex as other guides, keyed on client_ip + `/token`/`/auth` endpoints.

## JVM version + flag verification
```bash
docker exec keycloak java -version 2>&1        # container
docker exec keycloak cat /opt/java/openjdk/release 2>/dev/null || \
docker exec keycloak cat /opt/keycloak/release 2>/dev/null | grep JAVA_VERSION
ps -ef | grep '[k]eycloak' | grep -oE '\-XX:[^ ]*'
```
Vulnerable = OpenJDK 17.0.6+/21.x/25.x/27.x without a 4th version segment (bare "17.0.21" = vulnerable).

## Patch-check per vendor
- Keycloak images track upstream OpenJDK — rebuild using a FIXED base image (Temurin fixed build
  pending; Corretto 17.0.21.1.2+ / Oracle 17.0.21.1+4 are fixed).
- Rebuild required: patching the host JDK does NOT patch a container image's bundled runtime.
- Interim: restart with `-XX:-UseBASE64Intrinsics` (recommended) or `-XX:UseAVX=2` (x86-64 only — JVM
  fails to start on ARM).

## Post-exploit follow-up
- hs_err_pid logs under `<home>/data/` or the JVM working dir; exit-134 container restarts.
- Keycloak admin event log (Admin events / Login events): new realms, new admin tokens, token
  minting bursts from single client_ids.
- Process tree: JVM spawning shells (sigma spawn rules).
- Anomalous outbound TLS from the Keycloak identity (samczsun client-side vector); baseline egress
  to user federation stores/DBs/mail servers.
- Watch for JavaBleed-style mass reads: token/refresh grants over a heap-disclosure path, sudden
  response-body size spikes on `/token` responses.
