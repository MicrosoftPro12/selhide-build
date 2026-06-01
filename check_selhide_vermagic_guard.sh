#!/system/bin/sh
# One-click safe selhide module guard check.
#
# This never calls init_module(2). It only asks kallsyms_init_module to verify
# whether the selected .ko is exact-release or KMI/modversions compatible, then
# optionally runs the dry-run symbol resolver.

case "$0" in
    */*) SCRIPT_DIR="${0%/*}" ;;
    *) SCRIPT_DIR="." ;;
esac
cd "$SCRIPT_DIR" 2>/dev/null || true

OUT="${OUT:-./check_selhide_vermagic_guard_$(date +%Y%m%d_%H%M%S)_$$.txt}"
RUN_DRY_RUN="${RUN_DRY_RUN:-1}"

pick_file() {
    for p in "$@"; do
        [ -n "$p" ] || continue
        [ -f "$p" ] || continue
        echo "$p"
        return 0
    done
    return 1
}

pick_exec() {
    for p in "$@"; do
        [ -n "$p" ] || continue
        [ -f "$p" ] || continue
        [ -x "$p" ] || chmod 755 "$p" 2>/dev/null || true
        [ -x "$p" ] || continue
        echo "$p"
        return 0
    done
    return 1
}

select_ko() {
    if [ -n "${KO:-}" ] && [ -f "$KO" ]; then
        echo "$KO"
        return 0
    fi
    pick_file \
        ./selhide-android13-5.15.ko \
        ./selhide-android16-6.12.ko \
        ./selhide-renoir-5.4.147-qgki.ko \
        ./selhide-*.ko \
        ./*.ko
}

KO="$(select_ko 2>/dev/null || true)"
LOADER="${LOADER:-$(pick_exec ./kallsyms_init_module ../kallsyms_init_module /workdir/kallsyms_init_module 2>/dev/null || true)}"

log_section() {
    echo
    echo "== $* =="
}

find_reference_vermagic() {
    if [ -n "${SELHIDE_REFERENCE_VERMAGIC:-}" ]; then
        echo "env:SELHIDE_REFERENCE_VERMAGIC:$SELHIDE_REFERENCE_VERMAGIC"
        return 0
    fi
    if [ -n "${SELHIDE_REFERENCE_VERMAGIC_FILE:-}" ] &&
       [ -f "$SELHIDE_REFERENCE_VERMAGIC_FILE" ]; then
        ref="$(sed -n '1{s/[[:cntrl:]]*$//;p;}' "$SELHIDE_REFERENCE_VERMAGIC_FILE" 2>/dev/null)"
        [ -n "$ref" ] && echo "file:$SELHIDE_REFERENCE_VERMAGIC_FILE:$ref" && return 0
    fi
    for rf in ./reference_vermagic.txt ../reference_vermagic.txt; do
        [ -f "$rf" ] || continue
        ref="$(sed -n '1{s/[[:cntrl:]]*$//;p;}' "$rf" 2>/dev/null)"
        [ -n "$ref" ] || continue
        echo "file:$rf:$ref"
        return 0
    done

    for d in \
        /vendor/lib/modules \
        /vendor_dlkm/lib/modules \
        /odm/lib/modules \
        /odm_dlkm/lib/modules \
        /system/lib/modules \
        /system_dlkm/lib/modules \
        /lib/modules
    do
        [ -d "$d" ] || continue
        for p in "$d"/*.ko "$d"/*/*.ko "$d"/*/*/*.ko; do
            [ -f "$p" ] || continue
            ref="$(strings "$p" 2>/dev/null | sed -n 's/^vermagic=//p' | head -n 1)"
            [ -n "$ref" ] || continue
            echo "$p:$ref"
            return 0
        done
    done
    return 1
}

main() {
    rc=0

    log_section meta
    date
    uname -a
    id
    command -v getprop >/dev/null 2>&1 && {
        getprop ro.product.device
        getprop ro.build.version.release
        getprop ro.build.version.sdk
    }
    echo "pwd=$(pwd)"
    echo "ko=${KO:-missing}"
    echo "loader=${LOADER:-missing}"
    echo "run_dry_run=$RUN_DRY_RUN"

    log_section inputs
    [ -n "$KO" ] && [ -f "$KO" ] || { echo "ERROR: module not found"; return 2; }
    [ -n "$LOADER" ] && [ -x "$LOADER" ] || { echo "ERROR: loader not executable"; return 2; }
    ls -l "$KO" "$LOADER" 2>&1

    log_section module_info
    if command -v modinfo >/dev/null 2>&1; then
        modinfo "$KO" 2>/dev/null | sed -n '/^filename:/p;/^version:/p;/^vermagic:/p;/^parm:/p'
    fi
    strings "$KO" 2>/dev/null | grep -E '^(name|version|vermagic|parm|parmtype|depends)=' || true
    readelf -SW "$KO" 2>/dev/null | grep -E '(__versions|__version_ext|\.BTF)' || true

    log_section reference_vermagic
    find_reference_vermagic 2>/dev/null || echo "reference_vermagic=missing"

    log_section loader_check_vermagic
    "$LOADER" --check-vermagic "$KO"
    rc=$?
    echo "check_vermagic_exit=$rc"
    [ "$rc" = "0" ] || return "$rc"

    if [ "$RUN_DRY_RUN" = "1" ]; then
        log_section loader_dry_run
        "$LOADER" --dry-run "$KO"
        rc=$?
        echo "dry_run_exit=$rc"
    fi

    return "$rc"
}

main > "$OUT" 2>&1
rc=$?
echo "$OUT"
exit "$rc"
