#!/usr/bin/env bash
# Leak guard: fails when something that must never be public is tracked.
# Runs in CI on every push and pull request, and locally from the pre-push
# hook (.githooks/pre-push). Pure git + grep, no network, no dependencies.
#
#   scripts/leak-guard.sh            check the files tracked at HEAD
#   scripts/leak-guard.sh <range>    also check commit metadata in <range>
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
fail=0
say() { printf 'leak-guard: %s\n' "$*" >&2; fail=1; }

# 1. Paths that have no business in a public tool repository.
forbidden_paths='(^|/)(\.env(\..*)?|\.dev\.vars|\.mcp\.json|\.DS_Store|id_rsa|id_ed25519)$|\.(pem|p12|pfx|key|kdbx)$|(^|/)(\.claude|\.agents|\.hermes|\.wrangler)/|^(blog|docs|drafts|notes|research|source-pages|skill-claude)/|(^|/)(PUBLISH-CHECKLIST|fact-base|research-brief)[^/]*\.md$|^dist/'
if hits=$(git ls-files | grep -E "$forbidden_paths"); then
  say "tracked files that must not be published:"; printf '  %s\n' $hits >&2
fi

# 2. Markdown is limited to the public documents. Internal notes are
#    markdown; anything new has to be added here on purpose.
allowed_md='^(README|SECURITY|CONTRIBUTING|CHANGELOG)\.md$|^detections/(README\.md|hunt-guides/[a-z0-9-]+\.md)$|^vendor/'
if hits=$(git ls-files '*.md' | grep -Ev "$allowed_md"); then
  say "markdown outside the public allowlist (edit scripts/leak-guard.sh if intended):"; printf '  %s\n' $hits >&2
fi

# 3. Content markers: local home-directory paths, internal labels, and
#    references to internal working documents.
markers='/(Users|home)/[A-Za-z0-9._-]+/|PUBLISH CHECK|INTERNAL ONLY|DO NOT PUBLISH|docs/fact-base|docs/research\.md|source-pages/'
if hits=$(git grep -nIE "$markers" -- . ':!vendor' ':!scripts/leak-guard.sh' ':!*_test.go' ':!testdata' ':!detections' 2>/dev/null); then
  say "internal markers in tracked content:"; printf '%s\n' "$hits" | cut -c1-200 | sed 's/^/  /' >&2
fi

# 4. Commit metadata: a machine-local address (user@host.local) publishes the
#    workstation's user and host name with every commit.
range="${1:-HEAD}"
if hits=$(git log --format='%h %ae %ce' "$range" 2>/dev/null | grep -E '(@|\.)(local|localdomain|lan|internal)( |$)'); then
  say "commits with a machine-local author or committer email:"; printf '%s\n' "$hits" | sed 's/^/  /' >&2
  printf '  fix: git config user.email <public address>, then amend or rebase\n' >&2
fi

if [ "$fail" -ne 0 ]; then
  printf 'leak-guard: FAILED\n' >&2
  exit 1
fi
printf 'leak-guard: ok\n'
