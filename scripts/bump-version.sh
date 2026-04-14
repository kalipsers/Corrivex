#!/usr/bin/env bash
# Bump Corrivex to a new SemVer in lock-step across all four locations:
#   - internal/version/version.go
#   - cmd/server/versioninfo.json
#   - cmd/agent/versioninfo.json
#   - versioning.md (adds an empty changelog stub at the top of the Changelog)
#
# Usage:
#   ./scripts/bump-version.sh 1.2.3
#
# After this you still need to:
#   1. Fill in the new changelog entry in versioning.md (an empty section
#      header was inserted for you).
#   2. git add -A && git commit -m "release 1.2.3"
#   3. git push origin main
#   4. git tag v1.2.3 && git push origin v1.2.3
# The release.yml workflow takes over from there.

set -euo pipefail

NEW="${1:-}"
if [[ -z "$NEW" ]]; then
    echo "Usage: $0 X.Y.Z" >&2; exit 2
fi
if ! [[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Version must be MAJOR.MINOR.PATCH (got: $NEW)" >&2; exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IFS='.' read -r MAJOR MINOR PATCH <<<"$NEW"

# Find a working Python. Windows ships Microsoft-Store stubs at
# python.exe / python3.exe that exist on PATH but exit non-zero when run; we
# probe with --version to skip them and fall back to the `py` launcher.
PYTHON=
for cand in py python3 python; do
    if command -v "$cand" >/dev/null 2>&1 && "$cand" --version >/dev/null 2>&1; then
        PYTHON="$cand"
        break
    fi
done
if [[ -z "$PYTHON" ]]; then
    echo "Need python on PATH (tried: py, python3, python)." >&2; exit 1
fi

OLD=$(awk -F'"' '/^var Version =/{print $2; exit}' internal/version/version.go)
echo "  $OLD → $NEW"

# 1. internal/version/version.go
sed -i.bak "s/^var Version = \"[^\"]*\"/var Version = \"$NEW\"/" internal/version/version.go
rm -f internal/version/version.go.bak

# 2 + 3. versioninfo.json files (use python for safe JSON edits).
# Force UTF-8 explicitly — on Windows Python defaults to the system code
# page, which mangles em-dashes and the © sign.
"$PYTHON" - "$NEW" "$MAJOR" "$MINOR" "$PATCH" <<'PY'
import json, sys
new, M, m, p = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
for path in ("cmd/server/versioninfo.json", "cmd/agent/versioninfo.json"):
    with open(path, encoding='utf-8') as f: d = json.load(f)
    d['FixedFileInfo']['FileVersion']    = {'Major': M, 'Minor': m, 'Patch': p, 'Build': 0}
    d['FixedFileInfo']['ProductVersion'] = {'Major': M, 'Minor': m, 'Patch': p, 'Build': 0}
    d['StringFileInfo']['FileVersion']    = new
    d['StringFileInfo']['ProductVersion'] = new
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
        f.write('\n')
    print(f'  updated {path}')
PY

# 4. Insert an empty changelog stub at the top of the Changelog section.
"$PYTHON" - "$NEW" <<'PY'
import sys
new = sys.argv[1]
path = 'versioning.md'
with open(path, encoding='utf-8') as f: src = f.read()
stub = (
    f"### {new} \u2014 TODO short summary\n\n"
    "**Major / Minor / Patch** \u2014 describe the change.\n\n"
)
needle = "## Changelog\n\nNewest first. Each entry lists user-visible changes grouped by bump type.\n\n"
if needle not in src:
    print('versioning.md: could not find the Changelog header — please add the entry manually', file=sys.stderr)
    sys.exit(0)
src = src.replace(needle, needle + stub, 1)
with open(path, 'w', encoding='utf-8', newline='\n') as f: f.write(src)
print(f'  inserted stub into versioning.md (FILL IT IN before committing)')
PY

echo
echo "Done. Next steps:"
echo "  1. Edit versioning.md and replace the TODO stub with a real changelog entry."
echo "  2. git add -A && git commit -m \"release $NEW\""
echo "  3. git push origin main"
echo "  4. git tag v$NEW && git push origin v$NEW"
echo
echo "CI will build all binaries, create a GitHub Release, and push the Docker image."
