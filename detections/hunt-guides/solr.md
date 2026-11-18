# Java4Shell Hunt Guide — Apache Solr

Trigger: 64×'A'+'=' (65 chars), 128×'A'+'=' on JDK 17-class runtimes. Never send the
trigger at production stacks (Spring Security/Tomcat on Temurin 17.0.21+9 dies pre-auth).

## Where it runs
- Solr JVM (Jetty-embedded), :8983/solr, cloud mode on :9983 ZooKeeper coordinator.
- Post-auth RCE demonstrated by Calif (Kafka, Solr, Elasticsearch in the post-auth set).

## Decoder routes (exact endpoints/fields feeding Base64)
- Basic auth (`Authorization: Basic <b64>`) when security auth is on — decodes pre/early
  in the request chain via `java.util.Base64`.
- Binary/JavaBin `wt=javabin` response/request handling.
- Indexing payloads: binary field content sent base64-encoded (`b64` field types),
  UpdateRequestProcessor values.
- Replication/handlers exchanging base64-wrapped segment manifests.

## What to grep (exact commands)
```bash
# Linux
grep -rniE 'IllegalArgumentException' /var/solr/logs/solr.log | grep -iE 'base64|decode'
grep -hoE 'A{64}=|A{128}=' /var/solr/logs/solr-*-access.log 2>/dev/null
find /var/solr /opt/solr/server/logs -name 'hs_err_pid*.log' -newermt '-7 days'
# container
docker exec solr cat /opt/solr/server/solr/.. 2>/dev/null || docker exec solr java -version 2>&1
docker exec solr cat /opt/solr/.java_version 2>/dev/null || docker exec solr ls /opt/solr/server/
```
```bash
# macOS (homebrew)
find /usr/local/opt/solr* -name 'hs_err_pid*.log' 2>/dev/null
grep -rniE 'IllegalArgument' ~/solr-*/server/logs/solr.log
```
```bash
# Windows
findstr /S /R /I "hs_err_pid" "C:\solr*\server\logs\hs_err_pid*.log"
findstr /R /I "IllegalArgumentException" "C:\solr*\server\logs\solr.log"
```

## JVM version + flag verification
```bash
docker exec solr java -version 2>&1
docker exec solr bash -c 'cat $(dirname $(which java))/../release 2>/dev/null | grep -E "JAVA_VERSION|IMPLEMENTOR"'
ps -ef | grep '[s]olr' | grep -oE '\-XX:[^ ]*'
```
Vulnerable = OpenJDK 17.0.6+ / 21.x / 25.x / 27.x (Solr ships 17.x class with newer bundles) without the fix segment.

## Patch-check per vendor
- Solr releases bundle their own JDK — upgrade to a Solr build whose bundled JDK is in the
  fixed list (Corretto 17.0.21.1.2+ / Oracle 17.0.21.1+4; Temurin fixed build pending).
- Interim: `-XX:-UseBASE64Intrinsics` in `SOLR_JAVA_MEM` / solr.in.sh `GC_TUNE` or SOLR_OPTS.
- If Solr uses an OS JDK (rare), patch that directly.

## Post-exploit follow-up
- hs_err files under `/opt/solr/server/logs` and the JVM workdir; exit 134/139.
- Audit logs (`security.json` auditing plugin) for weird update handlers/collection create/delete.
- Process tree: JVM spawning shells/interpreters (sigma spawn rules).
- Anomalous outbound TLS from the Solr JVM identity to non-cluster ZK/collection hosts (samczsun
  client-side vector).
- JavaBleed: oversized docs / scroll responses with non-UTF garbage in fields.
