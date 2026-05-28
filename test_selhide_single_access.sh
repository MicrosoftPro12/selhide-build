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
KO="${KO:-./selhide-renoir-5.4.147-qgki.ko}"
LOADER="${LOADER:-./kallsyms_init_module}"
PARAMS="${PARAMS:-access_hook=1 clean_access=0}"
ACCESS="${ACCESS:-/sys/fs/selinux/access}"
ACCESS_TIMEOUT="${ACCESS_TIMEOUT:-8}"

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

guard_vermagic_before_load() {
    ko_release="$(strings "$KO" 2>/dev/null | sed -n 's/^vermagic=//p' | head -n 1 | awk '{print $1}')"
    running_release="$(uname -r)"

    echo "ko_release=${ko_release:-missing}"
    echo "running_release=$running_release"
    if [ -n "$ko_release" ] && [ "$ko_release" = "$running_release" ]; then
        echo "vermagic_guard=exact-release-match"
        return 0
    fi

    if [ "${ALLOW_UNSAFE_MODULE_LOAD:-}" = "YES" ]; then
        echo "vermagic_guard=override"
        return 0
    fi

    echo "ERROR: refusing to load vermagic-mismatched module"
    echo "       set ALLOW_UNSAFE_MODULE_LOAD=YES only for deliberate crash testing"
    return 4
}

cleanup_module() {
    if is_loaded; then
        log_section rmmod_cleanup
        rmmod selhide 2>&1
        echo "rmmod_exit=$?"
        grep '^selhide ' /proc/modules 2>&1 || echo "(not loaded)"
    fi
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

    log_section single_access_query
    single_access_query
    rc=$?

    log_section dmesg_after_query
    filtered_dmesg 260

    if [ "$rc" = "124" ]; then
        echo "skip rmmod after timeout to avoid unloading while a blocked transaction may still hold module text"
        return "$rc"
    fi

    cleanup_module

    log_section dmesg_after_rmmod
    filtered_dmesg 260

    return "$rc"
}

main > "$OUT" 2>&1
rc=$?
echo "$OUT"
exit "$rc"
