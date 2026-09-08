#!/system/bin/sh
# Find a clean SELinux binary policy for selhide and copy it into cwd.
#
# Intended use from a Magisk module post-fs-data/service script:
#   cd "$MODDIR"
#   sh ./find_clean_sepolicy_load.sh
#
# Outputs:
#   ./clean_sepolicy_load
#   ./clean_sepolicy_report.txt

set -u

OUT_DIR="${OUT_DIR:-$(pwd)}"
OUT="${OUT:-$OUT_DIR/clean_sepolicy_load}"
REPORT="${REPORT:-$OUT_DIR/clean_sepolicy_report.txt}"

log() {
    printf '%s\n' "$*" | tee -a "$REPORT" >/dev/null
}

reset_report() {
    mkdir -p "$OUT_DIR" 2>/dev/null || true
    : > "$REPORT"
    log "selhide clean sepolicy finder"
    log "date=$(date 2>/dev/null || true)"
    log "pwd=$(pwd)"
    log "out=$OUT"
}

file_size() {
    wc -c "$1" 2>/dev/null | awk '{print $1}'
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" 2>/dev/null | awk '{print $1}'
    else
        echo "sha256sum-missing"
    fi
}

is_probable_binary_policy() {
    p="$1"
    [ -f "$p" ] || return 1
    size="$(file_size "$p")"
    [ -n "$size" ] || return 1
    [ "$size" -gt 65536 ] || return 1
    [ "$size" -lt 33554432 ] || return 1

    # In basic grep syntax an unescaped '(' is literal. Avoid ERE groups here:
    # older Android grep implementations disagree on backslash handling.
    head -c 256 "$p" 2>/dev/null | grep -qa \
        -e '^(type ' \
        -e '^(allow ' \
        -e '^#' \
        -e '^type ' \
        -e '^allow ' && return 1
    return 0
}

copy_candidate() {
    src="$1"
    reason="$2"

    if ! is_probable_binary_policy "$src"; then
        log "skip: $src ($reason)"
        return 1
    fi

    cp -f "$src" "$OUT" 2>/dev/null || {
        log "copy failed: $src"
        return 1
    }
    chmod 0644 "$OUT" 2>/dev/null || true
    log "selected=$src"
    log "reason=$reason"
    log "size=$(file_size "$OUT")"
    log "sha256=$(sha256_file "$OUT")"
    return 0
}

inventory_split_policy() {
    log ""
    log "split-policy inventory:"
    for d in \
        /system/etc/selinux \
        /system_ext/etc/selinux \
        /product/etc/selinux \
        /vendor/etc/selinux \
        /odm/etc/selinux \
        /system_dlkm/etc/selinux \
        /vendor_dlkm/etc/selinux
    do
        [ -d "$d" ] || continue
        find "$d" -maxdepth 1 -type f 2>/dev/null \
            | grep -E \
                -e '/precompiled_sepolicy' \
                -e '\.cil$' \
                -e '\.compat\.cil$' \
                -e '\.sha256$' \
            | sort \
            | while IFS= read -r f; do
                log "  $(file_size "$f") $(sha256_file "$f") $f"
            done
    done
}

main() {
    reset_report

    # Best case: Magisk already saved the original binary policy before patching.
    for p in \
        /debug_ramdisk/.magisk/selinux/load \
        /sbin/.magisk/selinux/load \
        /dev/.magisk/selinux/load \
        /data/adb/magisk/selinux/load
    do
        copy_candidate "$p" "magisk-original-backup" && exit 0
    done

    # Split-policy devices usually carry a binary precompiled policy on disk.
    for p in \
        /vendor/etc/selinux/precompiled_sepolicy \
        /odm/etc/selinux/precompiled_sepolicy \
        /product/etc/selinux/precompiled_sepolicy \
        /system_ext/etc/selinux/precompiled_sepolicy \
        /system/etc/selinux/precompiled_sepolicy \
        /sepolicy \
        /first_stage_ramdisk/sepolicy
    do
        copy_candidate "$p" "device-binary-policy" && exit 0
    done

    inventory_split_policy
    log ""
    log "ERROR: no loadable clean binary policy found"
    log "note: CIL split policies need userspace compilation before selhide can use them."
    exit 2
}

main "$@"
