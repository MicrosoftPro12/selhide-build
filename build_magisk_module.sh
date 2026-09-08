#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$ROOT/magisk-module"
OUT="$PWD/selhide-magisk-experimental.zip"
LOADER=""
declare -a MODULE_SPECS=()

usage() {
    cat <<'EOF'
Usage: build_magisk_module.sh --loader FILE --module RELEASE=KO [options]

Options:
  --loader FILE          Static arm64 kallsyms_init_module binary
  --module RELEASE=KO    Add an exact uname -r artifact; repeat as needed
  --out FILE             Output zip path
  -h, --help             Show this help
EOF
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

while (($#)); do
    case "$1" in
        --loader)
            (($# >= 2)) || die "--loader requires a file"
            LOADER="$2"; shift 2 ;;
        --module)
            (($# >= 2)) || die "--module requires RELEASE=KO"
            MODULE_SPECS+=("$2"); shift 2 ;;
        --out)
            (($# >= 2)) || die "--out requires a file"
            OUT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -d "$TEMPLATE" ]] || die "module template missing: $TEMPLATE"
[[ -x "$LOADER" ]] || { echo "loader is missing or not executable: $LOADER" >&2; exit 3; }
((${#MODULE_SPECS[@]} > 0)) || { echo "at least one --module is required" >&2; exit 4; }
command -v zip >/dev/null || { echo "missing command: zip" >&2; exit 5; }
command -v sha256sum >/dev/null || { echo "missing command: sha256sum" >&2; exit 5; }

mkdir -p "$(dirname "$OUT")"
OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"

stage="$(mktemp -d "${TMPDIR:-/tmp}/selhide-magisk.XXXXXX")"
archive="$stage.zip"
trap 'rm -rf "$stage"; rm -f "$archive"' EXIT
cp -a "$TEMPLATE/." "$stage/"
mkdir -p "$stage/bin" "$stage/payload/modules"
cp "$LOADER" "$stage/bin/kallsyms_init_module"
cp "$ROOT/find_clean_sepolicy_load.sh" "$stage/bin/find_clean_sepolicy_load.sh"
chmod 0755 "$stage/bin/kallsyms_init_module" "$stage/bin/find_clean_sepolicy_load.sh"

manifest="$stage/payload/manifest.tsv"
printf '%s\n' '# exact_kernel_release|relative_module_path|sha256|label' > "$manifest"
for spec in "${MODULE_SPECS[@]}"; do
    release="${spec%%=*}"
    ko="${spec#*=}"
    [[ -n "$release" && "$ko" != "$spec" && -f "$ko" ]] || {
        echo "invalid module spec: $spec" >&2
        exit 6
    }
    safe_release="$(printf '%s' "$release" | tr -c 'A-Za-z0-9._-' '_')"
    rel="payload/modules/$safe_release/selhide.ko"
    mkdir -p "$stage/${rel%/*}"
    cp "$ko" "$stage/$rel"
    sha="$(sha256sum "$stage/$rel" | awk '{print $1}')"
    printf '%s|%s|%s|%s\n' "$release" "$rel" "$sha" "$release" >> "$manifest"
done

find "$stage" -type f -name '*.sh' -exec chmod 0755 {} +
(
    cd "$stage"
    zip -qr "$archive" .
)
mv -f "$archive" "$OUT"

echo "$OUT"
sha256sum "$OUT"
