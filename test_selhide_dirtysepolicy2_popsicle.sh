#!/system/bin/sh
# One-shot popsicle/Android 16 DirtySepolicy 2.x selhide smoke test.
#
# Run from Android host/root shell in the directory containing:
#   ./selhide-popsicle-android16-6.12-dsp2-exp.ko
#   ./kallsyms_init_module
#
# The full log is always written to the current directory.

case "$0" in
    */*) SCRIPT_DIR="${0%/*}" ;;
    *) SCRIPT_DIR="." ;;
esac
cd "$SCRIPT_DIR" 2>/dev/null || true

OUT="${OUT:-./test_selhide_dirtysepolicy2_popsicle_$(date +%Y%m%d_%H%M%S).txt}"
LOADER="${LOADER:-./kallsyms_init_module}"
DO_LOAD="${DO_LOAD:-1}"
RUN_PROBES="${RUN_PROBES:-1}"
AUTO_RMMOD="${AUTO_RMMOD:-1}"
HOLD_SECONDS="${HOLD_SECONDS:-0}"
RUN_APP="${RUN_APP:-0}"
APP_PKG="${APP_PKG:-org.lsposed.dirtysepolicy}"
APP_WAIT_SECONDS="${APP_WAIT_SECONDS:-8}"
KMSG_MARK="selhide_test_$$_$(date +%s 2>/dev/null)"
KMSG_MARKED=0

select_ko() {
    if [ -n "${KO:-}" ] && [ -f "$KO" ]; then
        echo "$KO"
        return 0
    fi
    for candidate in \
        ./selhide-popsicle-android16-6.12-dsp2-exp.ko \
        ./selhide-android16-6.12.ko \
        ./selhide-*.ko \
        ./*.ko
    do
        [ -f "$candidate" ] || continue
        echo "$candidate"
        return 0
    done
    return 1
}

select_policy() {
    if [ -n "${POLICY_PATH:-}" ] && [ -f "$POLICY_PATH" ]; then
        echo "$POLICY_PATH"
        return 0
    fi
    for candidate in \
        /debug_ramdisk/.magisk/selinux/load \
        ./load \
        ./clean-load.bin \
        /workdir/load
    do
        [ -f "$candidate" ] || continue
        echo "$candidate"
        return 0
    done
    return 1
}

KO="$(select_ko 2>/dev/null || true)"
POLICY_PATH="$(select_policy 2>/dev/null || true)"
PARAMS="${PARAMS:-access_hook=1 clean_access=1 context_hook=1 setprocattr_hook=1 policy_path=$POLICY_PATH}"

log_section() {
    echo
    echo "== $* =="
}

is_loaded() {
    grep -q '^selhide ' /proc/modules 2>/dev/null
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
    case "$(uname -r)" in
        6.12.*android16*) ;;
        *) echo "WARN: this script was prepared for popsicle Android16/6.12, running_release=$(uname -r)" ;;
    esac
    return 0
}

filtered_dmesg() {
    if [ "$KMSG_MARKED" = "1" ]; then
        dmesg 2>/dev/null | sed -n "/$KMSG_MARK start/,\$p"
    else
        dmesg 2>/dev/null
    fi | grep -iE 'selhide|SEL_ACCESS|SEL_CONTEXT|setprocattr|clean_|module|vermagic|version magic|exec format|kallsyms|cfi|kcfi|fpac|oops|panic|Unable to handle|Internal error|Call trace|cut here|WARNING:' | tail -n "${1:-260}"
}

mark_kernel_log() {
    tag="$1"
    if [ -e /dev/kmsg ]; then
        echo "$KMSG_MARK $tag" > /dev/kmsg 2>/dev/null && KMSG_MARKED=1
    fi
}

print_module_info() {
    if command -v modinfo >/dev/null 2>&1; then
        modinfo "$KO" 2>/dev/null | sed -n '/^filename:/p;/^version:/p;/^vermagic:/p;/^parm:/p'
    fi
    strings "$KO" 2>/dev/null | grep -E '^(name|version|vermagic|parm|parmtype|depends)='
    echo "running_release=$(uname -r)"
}

write_selinux_context() {
    label="$1"
    ctx="$2"
    tmp="./.selhide_context_$$.out"
    (
        exec 3<> /sys/fs/selinux/context || exit 11
        printf '%s' "$ctx" >&3 || exit 12
        dd bs=4096 count=1 <&3 2>/dev/null
        exit $?
    ) > "$tmp" 2>&1
    probe_rc=$?
    echo "$label sysfs_context rc=$probe_rc raw=$(tr '\n' ' ' < "$tmp" 2>/dev/null)"
    rm -f "$tmp"
}

write_attr_current() {
    label="$1"
    ctx="$2"
    tmp="./.selhide_attr_$$.out"
    (
        printf '%s' "$ctx" > /proc/self/attr/current
    ) > "$tmp" 2>&1
    probe_rc=$?
    echo "$label attr_current rc=$probe_rc raw=$(tr '\n' ' ' < "$tmp" 2>/dev/null)"
    rm -f "$tmp"
}

probe_body() {
    echo "probe_id=$(id 2>/dev/null)"
    echo "probe_ctx=$(cat /proc/self/attr/current 2>/dev/null)"
    write_selinux_context "clean app_zygote" "u:r:app_zygote:s0"
    write_selinux_context "dirty magisk domain" "u:r:magisk:s0"
    write_selinux_context "dirty adbroot domain" "u:r:adbroot:s0"
    write_selinux_context "dirty ksu domain" "u:r:ksu:s0"
    write_selinux_context "dirty magisk file" "u:object_r:magisk_file:s0"
    write_selinux_context "dirty ksu file" "u:object_r:ksu_file:s0"
    write_selinux_context "dirty lsposed file" "u:object_r:lsposed_file:s0"
    write_attr_current "dirty magisk domain" "u:r:magisk:s0"
    write_attr_current "dirty adbroot domain" "u:r:adbroot:s0"
    write_attr_current "dirty ksu domain" "u:r:ksu:s0"
}

run_context_probes() {
    if command -v su >/dev/null 2>&1 && su -Z u:r:app_zygote:s0 -c 'cat /proc/self/attr/current >/dev/null' >/dev/null 2>&1; then
        echo "-- su -Z u:r:app_zygote:s0 --"
        su -Z u:r:app_zygote:s0 -c "$(sed -n '/^write_selinux_context()/,/^main()/p' "$0" | sed '$d'); probe_body" 2>&1
    else
        echo "-- current shell context fallback --"
        probe_body
    fi
}

launch_dirtysepolicy_app() {
    monkey_rc=127
    am_rc=127
    component=""

    if command -v monkey >/dev/null 2>&1; then
        monkey -p "$APP_PKG" -c android.intent.category.LAUNCHER 1 2>&1
        monkey_rc=$?
        echo "monkey_exit=$monkey_rc"
        [ "$monkey_rc" = "0" ] && return 0
    else
        echo "SKIP: monkey not available"
    fi

    if command -v cmd >/dev/null 2>&1; then
        component="$(cmd package resolve-activity --brief "$APP_PKG" 2>/dev/null | tail -n 1 | tr -d '\r')"
        case "$component" in
            */*) echo "resolved_activity=$component" ;;
            *)
                component="$(cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER "$APP_PKG" 2>/dev/null | tail -n 1 | tr -d '\r')"
                case "$component" in
                    */*) echo "resolved_activity=$component" ;;
                    *) echo "resolved_activity=$component"; component="" ;;
                esac
                ;;
        esac
    fi

    if command -v am >/dev/null 2>&1; then
        if [ -n "$component" ]; then
            am start -n "$component" 2>&1
            am_rc=$?
            echo "am_start_component_exit=$am_rc"
        else
            am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p "$APP_PKG" 2>&1
            am_rc=$?
            echo "am_start_package_exit=$am_rc"
        fi
        return "$am_rc"
    fi

    echo "SKIP: am not available"
    return "$monkey_rc"
}

cleanup_module() {
    if is_loaded; then
        log_section rmmod_cleanup
        rmmod selhide 2>&1
        echo "rmmod_exit=$?"
        grep '^selhide ' /proc/modules 2>&1 || echo "(not loaded)"
    fi
}

main() {
    main_rc=0

    log_section meta
    date
    uname -a
    id
    command -v getprop >/dev/null 2>&1 && {
        getprop ro.product.device
        getprop ro.build.version.release
        getprop ro.build.type
    }
    echo "ko=$KO"
    echo "loader=$LOADER"
    echo "policy_path=$POLICY_PATH"
    echo "params=$PARAMS"
    echo "do_load=$DO_LOAD"
    echo "run_probes=$RUN_PROBES"
    echo "auto_rmmod=$AUTO_RMMOD"
    echo "hold_seconds=$HOLD_SECONDS"
    echo "run_app=$RUN_APP"
    echo "app_pkg=$APP_PKG"
    echo "app_wait_seconds=$APP_WAIT_SECONDS"

    log_section host_guard
    guard_host || return 2
    mark_kernel_log start
    echo "kmsg_mark=$KMSG_MARK marked=$KMSG_MARKED"
    [ -n "$KO" ] && [ -f "$KO" ] || { echo "ERROR: module not found"; return 2; }
    [ -x "$LOADER" ] || { echo "ERROR: loader not executable: $LOADER"; return 2; }
    [ -n "$POLICY_PATH" ] && [ -f "$POLICY_PATH" ] || { echo "ERROR: clean policy load not found"; return 2; }
    ls -l "$KO" "$LOADER" "$POLICY_PATH" 2>&1

    log_section module_info
    print_module_info

    log_section kallsyms_dry_run
    "$LOADER" --dry-run "$KO"
    dry=$?
    echo "dry_run_exit=$dry"
    [ "$dry" = "0" ] || return "$dry"

    if [ "$DO_LOAD" != "1" ]; then
        echo "skip load: DO_LOAD=$DO_LOAD"
        return 0
    fi

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
        filtered_dmesg 260
        return "$load"
    fi

    log_section dmesg_after_load
    filtered_dmesg 260

    if [ "$RUN_PROBES" = "1" ]; then
        log_section context_and_setprocattr_probes
        run_context_probes
        log_section dmesg_after_probes
        filtered_dmesg 320
    fi

    if [ "$RUN_APP" = "1" ]; then
        log_section dirtysepolicy_app
        if command -v am >/dev/null 2>&1; then
            am force-stop "$APP_PKG" 2>&1 || true
        fi
        launch_dirtysepolicy_app || true
        sleep "$APP_WAIT_SECONDS"
        if command -v logcat >/dev/null 2>&1; then
            logcat -d -t 300 2>/dev/null | grep -iE 'DirtySepolicy|dirty sepolicy|no dirty|not found|WARNING:|ERROR:' || true
        else
            echo "SKIP: logcat not available"
        fi
        if command -v am >/dev/null 2>&1; then
            am force-stop "$APP_PKG" 2>&1 || true
        fi
        log_section dmesg_after_app
        filtered_dmesg 360
    fi

    if [ "$HOLD_SECONDS" != "0" ]; then
        log_section hold
        echo "sleeping ${HOLD_SECONDS}s"
        sleep "$HOLD_SECONDS"
        filtered_dmesg 260
    fi

    if [ "$AUTO_RMMOD" = "1" ]; then
        cleanup_module
        log_section dmesg_after_rmmod
        filtered_dmesg 320
    fi

    log_section verdict
    if is_loaded; then
        echo "RESULT: WARN selhide still loaded"
    else
        echo "RESULT: PASS script completed"
    fi
    mark_kernel_log end

    return "$main_rc"
}

main > "$OUT" 2>&1
main_rc=$?
echo "$OUT"
exit "$main_rc"
