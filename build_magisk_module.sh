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

kernel_requires_kcfi_entry() {
    local release="$1"
    local major minor

    [[ "$release" =~ ^([0-9]+)\.([0-9]+) ]] || return 1
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    ((major > 6 || (major == 6 && minor >= 1)))
}

symbol_prefix_u32() {
    local ko="$1"
    local symbol="$2"
    local symbol_info value section section_offset file_offset

    symbol_info="$(readelf -sW "$ko" | awk -v symbol="$symbol" '
        $8 == symbol { print $2, $7; exit }
    ')"
    read -r value section <<< "$symbol_info"
    [[ "$value" =~ ^[0-9a-fA-F]+$ && "$section" =~ ^[0-9]+$ ]] || return 1
    ((16#$value >= 4)) || return 1

    section_offset="$(readelf -SW "$ko" | sed -nE \
        "s/^[[:space:]]*\\[[[:space:]]*$section\\][[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+([^[:space:]]+).*/\\1/p" | head -n 1)"
    [[ "$section_offset" =~ ^[0-9a-fA-F]+$ ]] || return 1
    file_offset=$((16#$section_offset + 16#$value - 4))
    od -An -j "$file_offset" -N 4 -tx4 "$ko" | tr -d '[:space:]'
}

validate_kcfi_entry() {
    local release="$1"
    local ko="$2"
    local init_word cleanup_word

    kernel_requires_kcfi_entry "$release" || return 0
    init_word="$(symbol_prefix_u32 "$ko" init_module || true)"
    cleanup_word="$(symbol_prefix_u32 "$ko" cleanup_module || true)"
    [[ "$init_word" == 6fbb3035 && "$cleanup_word" == e5c47d60 ]] ||
        die "invalid KCFI module entry metadata for $release: init=${init_word:-missing} cleanup=${cleanup_word:-missing}"
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
command -v readelf >/dev/null || { echo "missing command: readelf" >&2; exit 5; }
command -v od >/dev/null || { echo "missing command: od" >&2; exit 5; }

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
    validate_kcfi_entry "$release" "$ko"
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
