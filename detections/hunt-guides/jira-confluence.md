# Java4Shell Hunt Guide — Atlassian Jira + Confluence

Trigger: 64×'A'+'=' (65 chars), 128×'A'+'=' on JDK 17-class runtimes. Never send the
trigger at production stacks (Spring Security/Tomcat on Temurin 17.0.21+9 dies pre-auth).

## Where it runs
- Jira Software Server/DC (:8080) and Confluence Server/DC (:8090), both shipping a bundled
  JRE under `<install>/jre/` — that bundled JRE is the vulnerable surface, not only the OS JDK.
- Pre-auth RCE demonstrated by Calif on default config for both products.

## Decoder routes (exact endpoints/fields feeding Base64)
- HTTP Basic and session-cookie flows through Tomcat/Atlassian's auth chain — the
  `Authorization: Basic <b64>` header decodes via `java.util.Base64` pre-auth.
- REST API token auth (`/rest/api/*` with `Authorization: Bearer`), PATs in request headers.
- Attachment/avatar upload endpoints and webhook payloads in parts.
- SAML/OAuth plugin exchanges (base64-wrapped assertions) and mail/attachment mime handling.
- Jira: `/rest/auth/1/session`, `/issues/` attachment POSTs. Confluence: `/rest/api/content`, plugin upload paths.

## What to grep (exact commands)
```bash
# Linux
grep -rniE 'IllegalArgumentException' <install>/logs/atlassian-jira.log | grep -iE 'base64|decode'
grep -rniE 'IllegalArgumentException' <install>/logs/atlassian-confluence.log | grep -iE 'base64|decode'
grep -hoE 'A{64}=|A{128}=' <install>/logs/access*.log 2>/dev/null
ls -lt <install>/jira/hs_err_pid*.log <install>/confluence/hs_err_pid*.log 2>/dev/null
```
```bash
# Windows bundle (service runs as a user; logs under ProgramData\Atlassian)
findstr /S /R /I "hs_err_pid" "C:\ProgramData\Atlassian\Application\*\jre\..\logs\*"
findstr /R /I "IllegalArgumentException" "C:\ProgramData\Atlassian\*\logs\atlassian-*.log"
```
- IAE-burst per client IP on `/catalina.out` or access logs: `(?i)IllegalArgumentException` + `(?i)base64|decoder`.

## JVM version + flag verification
```bash
<install>/jre/bin/java -version 2>&1            # Linux/macOS (bundled JRE)
docker exec jira cat /opt/atlassian/jira/jre/release | grep -E 'JAVA_VERSION|IMPLEMENTOR'
# Windows: <install>\jre\bin\java.exe -version
ps -ef | grep '[j]ava' | grep -oE '\-XX:[^ ]*'
```

## Patch-check per vendor
- Jira/Confluence DC releases rebuilt AFTER the OpenJDK fix carry a patched bundled JRE — check
  the bundled JRE version itself (17.0.21.1.1 fixed builds etc.), not the marketing release number.
- Corretto 17.0.21.1.2+ / Oracle 17.0.21.1+4 / Temurin: fixed build pending (17.0.21+9 vulnerable).
- Also verify the OS JDKs used by external agents/scale sets.

## Post-exploit follow-up
- hs_err logs in `<install>/<product>/` and `<home>/jira-log-dir` / `<home>/confluence` — fatal-error
  frames referencing Base64/deeply-nested AVX stubs indicate the trigger crash.
- New/unknown admin users, changed global permissions, new OAuth plugin installs (audit tables).
- Unexpected child processes of the Tomcat java process (sh/bash/python/certutil) — sigma spawn rules.
- Anomalous outbound TLS from the product's JVM identity (samczsun client-side vector); baseline
  its known-legit egress (Atlassian update servers, mail relay, proxy) and treat the rest as leads.
- JavaBleed-style reads: sudden large GET responses from heap-disclosure chains, mass attachment downloads.
