#!/system/bin/sh
# Minimal one-shot selhide access-hook test for Android host/root shell.
#
# Run from the directory containing:
#   ./selhide-renoir-5.4.147-qgki.ko
#   ./kallsyms_init_module
#
# Defaults:
#   - load with access_hook=1 clean_access=0
#   - perform exactly one /sys/fs/selinux/access transaction
#   - unload selhide if the transaction returns
#   - write the full log into the current directory

case "$0" in
    */*) SCRIPT_DIR="${0%/*}" ;;
    *) SCRIPT_DIR="." ;;
esac
cd "$SCRIPT_DIR" 2>/dev/null || true

OUT="${OUT:-./test_selhide_single_access_$(date +%Y%m%d_%H%M%S).txt}"
LOADER="${LOADER:-./kallsyms_init_module}"
PARAMS="${PARAMS:-access_hook=1 clean_access=0}"
ACCESS="${ACCESS:-/sys/fs/selinux/access}"
ACCESS_TIMEOUT="${ACCESS_TIMEOUT:-8}"
ALLOW_QUERY_WRITE_FAIL="${ALLOW_QUERY_WRITE_FAIL:-1}"

select_ko() {
    if [ -n "${KO:-}" ] && [ -f "$KO" ]; then
        echo "$KO"
        return 0
    fi
    for candidate in \
        ./selhide-android13-5.15.ko \
        ./selhide-android16-6.12.ko \
        ./selhide-renoir-5.4.147-qgki.ko \
        ./selhide-*.ko \
        ./*.ko
    do
        [ -f "$candidate" ] || continue
        echo "$candidate"
        return 0
    done
    return 1
}

KO="$(select_ko 2>/dev/null || true)"

log_section() {
    echo
    echo "== $* =="
}

is_loaded() {
    grep -q '^selhide ' /proc/modules 2>/dev/null
}

filtered_dmesg() {
    dmesg 2>/dev/null | grep -iE 'selhide|SEL_ACCESS|clean_access|module|vermagic|version magic|exec format|kallsyms|cfi|kcfi|fpac|oops|panic|Unable to handle|Internal error|Call trace' | tail -n "${1:-220}"
}

selhide_access_hit_count() {
    dmesg 2>/dev/null | grep -c 'selhide: SEL_ACCESS .*hit' 2>/dev/null || echo 0
}

guard_host() {
    if [ "$(id -u 2>/dev/null)" != "0" ]; then
        echo "ERROR: run from Android host root shell"
        return 1
    fi
    if [ -f /.dockerenv ] && [ "${ALLOW_CONTAINER:-0}" != "1" ]; then
        echo "ERROR: refusing to run inside a container"
        return 1
    fi
    if [ ! -e /proc/kallsyms ] || [ ! -d /sys/fs/selinux ]; then
        echo "ERROR: this does not look like the Android host kernel namespace"
        return 1
    fi
    return 0
}

print_module_info() {
    if command -v modinfo >/dev/null 2>&1; then
        modinfo "$KO" 2>/dev/null | sed -n '/^filename:/p;/^version:/p;/^vermagic:/p;/^parm:/p'
    fi
    strings "$KO" 2>/dev/null | grep -E '^(name|version|vermagic|parm|parmtype|depends)='
    echo "running_release=$(uname -r)"
}

extract_vermagic() {
    strings "$1" 2>/dev/null | sed -n 's/^vermagic=//p' | head -n 1
}

vermagic_release() {
    v="$1"
    echo "${v%% *}"
}

vermagic_suffix() {
    v="$1"
    case "$v" in
        *" "*) echo "${v#* }" ;;
        *) echo "" ;;
    esac
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
            ref="$(extract_vermagic "$p")"
            [ -n "$ref" ] || continue
            echo "$p:$ref"
            return 0
        done
    done
    return 1
}

guard_vermagic_before_load() {
    ko_vermagic="$(extract_vermagic "$KO")"
    ko_release="$(vermagic_release "$ko_vermagic")"
    ko_suffix="$(vermagic_suffix "$ko_vermagic")"
    running_release="$(uname -r)"
    ref_line="$(find_reference_vermagic 2>/dev/null || true)"
    case "$ref_line" in
        env:SELHIDE_REFERENCE_VERMAGIC:*)
            ref_path="env:SELHIDE_REFERENCE_VERMAGIC"
            ref_vermagic="${ref_line#env:SELHIDE_REFERENCE_VERMAGIC:}"
            ;;
        file:*:*)
            ref_path="${ref_line#file:}"
            ref_path="${ref_path%%:*}"
            ref_vermagic="${ref_line#file:$ref_path:}"
            ref_path="file:$ref_path"
            ;;
        *)
            ref_path="${ref_line%%:*}"
            ref_vermagic="${ref_line#*:}"
            ;;
    esac
    if [ -z "$ref_line" ] || [ "$ref_line" = "$ref_vermagic" ]; then
        ref_path=""
        ref_vermagic=""
    fi
    ref_suffix="$(vermagic_suffix "$ref_vermagic")"
    ref_release="$(vermagic_release "$ref_vermagic")"
    ref_release_match=0
    [ -n "$ref_release" ] && [ "$ref_release" = "$running_release" ] && ref_release_match=1

    echo "ko_release=${ko_release:-missing}"
    echo "running_release=$running_release"
    echo "ko_vermagic=${ko_vermagic:-missing}"
    echo "ko_vermagic_suffix=${ko_suffix:-missing}"
    echo "reference_module=${ref_path:-missing}"
    echo "reference_vermagic=${ref_vermagic:-missing}"
    echo "reference_vermagic_suffix=${ref_suffix:-missing}"
    echo "reference_release_match=$ref_release_match"

    if [ -n "$ko_release" ] && [ "$ko_release" = "$running_release" ] &&
       { [ -z "$ref_suffix" ] || [ "$ko_suffix" = "$ref_suffix" ] || [ "$ref_release_match" = "0" ]; }; then
        echo "vermagic_guard=exact-release-match"
        return 0
    fi

    if [ -n "$ko_suffix" ] && [ -n "$ref_suffix" ] && [ "$ko_suffix" = "$ref_suffix" ] &&
       { [ "$ref_release_match" = "1" ] || [ "${ALLOW_REFERENCE_RELEASE_MISMATCH:-}" = "YES" ]; }; then
        echo "vermagic_guard=kmi-suffix-candidate-loader-enforced"
        return 0
    fi

    if [ "${ALLOW_UNSAFE_MODULE_LOAD:-}" = "YES" ]; then
        echo "vermagic_guard=override"
        return 0
    fi

    echo "vermagic_guard=loader-enforced-mismatch"
    echo "INFO: final vermagic/modversions decision is enforced by kallsyms_init_module"
    return 0
}

cleanup_module() {
    if is_loaded; then
        cleanup_rc=0
        log_section rmmod_cleanup
        rmmod selhide 2>&1
        cleanup_rc=$?
        echo "rmmod_exit=$cleanup_rc"
        grep '^selhide ' /proc/modules 2>&1 || echo "(not loaded)"
        return "$cleanup_rc"
    fi
    return 0
}

single_access_query() {
    class_idx="$(cat /sys/fs/selinux/class/process/index 2>/dev/null)" || class_idx=""
    if [ -z "$class_idx" ]; then
        echo "ERROR: missing process class index"
        return 2
    fi

    qout="./.selhide_single_access.$$.$(date +%s).out"
    qrc="./.selhide_single_access.$$.$(date +%s).rc"
    rm -f "$qout" "$qrc"

    (
        exec 3<> "$ACCESS" || exit 11
        printf '%s %s %s' 'u:r:app_zygote:s0' 'u:r:isolated_app:s0' "$class_idx" >&3 || exit 12
        dd bs=4096 count=1 <&3 2>/dev/null
        exit $?
    ) > "$qout" 2>&1 &

    qpid=$!
    waited=0
    timed_out=0
    while kill -0 "$qpid" 2>/dev/null; do
        if [ "$waited" -ge "$ACCESS_TIMEOUT" ]; then
            timed_out=1
            echo "query_timeout=${ACCESS_TIMEOUT}s pid=$qpid"
            kill -TERM "$qpid" 2>/dev/null || true
            sleep 1
            kill -KILL "$qpid" 2>/dev/null || true
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done

    if [ "$timed_out" = "0" ]; then
        wait "$qpid"
        qstatus=$?
    else
        qstatus=124
    fi

    echo "query_exit=$qstatus"
    echo "query_output=$(tr '\n' ' ' < "$qout" 2>/dev/null)"
    rm -f "$qout" "$qrc"
    return "$qstatus"
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
    }
    echo "ko=$KO"
    echo "loader=$LOADER"
    echo "params=$PARAMS"
    echo "access_timeout=$ACCESS_TIMEOUT"
    echo "allow_query_write_fail=$ALLOW_QUERY_WRITE_FAIL"

    log_section host_guard
    guard_host || return 2
    ls -l "$KO" "$LOADER" 2>&1 || return 2

    log_section module_info
    print_module_info

    log_section kallsyms_dry_run
    "$LOADER" --dry-run "$KO"
    dry=$?
    echo "dry_run_exit=$dry"
    [ "$dry" = "0" ] || return "$dry"

    log_section vermagic_guard
    guard_vermagic_before_load || return $?

    if is_loaded; then
        log_section stale_module_cleanup
        rmmod selhide 2>&1
        echo "stale_rmmod_exit=$?"
        if is_loaded; then
            echo "ERROR: selhide still loaded; aborting"
            return 3
        fi
    fi

    log_section load
    "$LOADER" "$KO" $PARAMS
    load=$?
    echo "load_exit=$load"
    if [ "$load" != "0" ]; then
        filtered_dmesg 240
        return "$load"
    fi

    log_section dmesg_after_load
    filtered_dmesg 220

    access_hits_before="$(selhide_access_hit_count)"
    echo "access_hits_before=$access_hits_before"

    log_section single_access_query
    single_access_query
    rc=$?

    log_section dmesg_after_query
    filtered_dmesg 260
    access_hits_after="$(selhide_access_hit_count)"
    echo "access_hits_after=$access_hits_after"

    if [ "$rc" != "0" ] && [ "$rc" != "124" ] &&
       [ "$ALLOW_QUERY_WRITE_FAIL" = "1" ] &&
       [ "${access_hits_after:-0}" -gt "${access_hits_before:-0}" ]; then
        echo "query_nonzero_ignored=$rc because SEL_ACCESS hook was hit in this run"
        rc=0
    fi

    if [ "$rc" = "124" ]; then
        echo "skip rmmod after timeout to avoid unloading while a blocked transaction may still hold module text"
        return "$rc"
    fi

    query_rc="$rc"
    cleanup_module
    cleanup_rc=$?

    log_section dmesg_after_rmmod
    filtered_dmesg 260

    if [ "$cleanup_rc" != "0" ]; then
        return "$cleanup_rc"
    fi

    if [ "$query_rc" != "0" ] && [ "$ALLOW_QUERY_WRITE_FAIL" = "1" ] && ! is_loaded; then
        echo "query_nonzero_ignored=$query_rc because module load/unload smoke completed"
        rc=0
    fi

    return "$rc"
}

main > "$OUT" 2>&1
rc=$?
echo "$OUT"
exit "$rc"
