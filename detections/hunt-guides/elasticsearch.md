# Java4Shell Hunt Guide — Elasticsearch

Trigger: 64×'A'+'=' (65 chars), 128×'A'+'=' on JDK 17-class runtimes. Never send the
trigger at production stacks (Spring Security/Tomcat on Temurin 17.0.21+9 dies pre-auth).

## Where it runs
- Elasticsearch data/master/coordination nodes on 9200 (HTTP) / 9300 (transport), plus
  Kibana (Node, not Java) for frontend. Post-auth RCE demonstrated by Calif.

## Decoder routes (exact endpoints/fields feeding Base64)
- Security API auth: `Authorization: Basic <b64>` / `Bearer <token>` — the basic
  credentials decode via `java.util.Base64` on every node.
- API key generation/verification (`/_security/api_key`), encoded API-key/id:secret pairs.
- Ingest pipelines (`base64` decode processor) — user-controlled script content in POST bodies.
- TLS certificate PEM handling in node/client cert loads.
- Note: Elasticsearch chain runs from ONE COMPLETE REQUEST — proxy body buffering does NOT
  block it here (documented exception to "buffering mitigates").

## What to grep (exact commands)
```bash
# Linux / container
docker exec es cat /usr/share/elasticsearch/jdk/release 2>/dev/null || \
docker exec es ls /usr/share/elasticsearch/jdk/ 2>/dev/null
grep -rniE 'IllegalArgumentException' /var/log/elasticsearch/*.log | grep -iE 'base64|decoder'
find /var/log/elasticsearch /var/lib/elasticsearch -name 'hs_err_pid*.log' -newermt '-7 days'
# macOS (homebrew)
find /usr/local/var/lib/elasticsearch -name 'hs_err_pid*.log'
```
```bash
# Windows service
findstr /S /R /I "hs_err_pid" "%ELASTIC_HOME%\logs\hs_err_pid*.log"
findstr /R /I "IllegalArgumentException" "%ELASTIC_HOME%\logs\*.log"
```
- IAE burst pattern per client_ip on the 9200 HTTP access log (`xpack.security.http.*` logs).

## JVM version + flag verification
```bash
docker exec es java -version 2>&1                  # bundled JDK
docker exec es cat /usr/share/elasticsearch/jdk/release | grep -E 'JAVA_VERSION|IMPLEMENTOR'
ps -ef | grep '[e]lasticsearch' | grep -oE '\-XX:[^ ]*'
```
Vulnerable = OpenJDK 17.0.6+ / 21.x / 25.x / 27.x without the 4th fix segment (bare "17.0.21" = vulnerable).

## Patch-check per vendor
- Elastic rebuilds ship a bundled JDK — upgrade Elasticsearch to a release on the FIXED
  JDK (Corretto 17.0.21.1.2+, Oracle 17.0.21.1+4). Temurin fixed build pending at disclosure.
- The bundled JDK path is what matters — an OS-level patched JDK does NOT help if ES uses its own.
- Interim mitigation on x86-64: `-XX:-UseBASE64Intrinsics` in `jvm.options` (not `UseAVX=2` on ARM).

## Post-exploit follow-up
- hs_err_pid logs under `/var/log/elasticsearch` (container JVM workdir too); exit 134/139 events.
- Audit logs (`xpack.security.audit`): unusual bulk/scroll searches from service accounts, API-key
  creation, unexpected index/ingest-pipeline changes.
- Process tree: JVM spawning shells (sigma spawn rules).
- Anomalous outbound TLS from ES JVM identity toward non-cluster hosts (samczsun client-side
  vector, replica/S3/plugin egress is the legit set).
- JavaBleed-style heap disclosure: sudden oversized `_source`/scroll responses with non-field bytes.
