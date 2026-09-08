#!/system/bin/sh

STATE_DIR="${SELHIDE_STATE_DIR:-/data/adb/selhide}"
LOG_FILE="$STATE_DIR/selhide.log"
STATUS_FILE="$STATE_DIR/status.env"
GUARD_FILE="$STATE_DIR/load_pending"
SAFE_MODE_FILE="$STATE_DIR/safe_mode"
AUTOLOAD_FILE="$STATE_DIR/autoload"
TRIAL_PASSED_FILE="$STATE_DIR/trial_passed"
APPLY_LIST_FILE="$STATE_DIR/apply-list.txt"
MANIFEST="$MODDIR/payload/manifest.tsv"
LOADER="$MODDIR/bin/kallsyms_init_module"
POLICY_FILE="$STATE_DIR/clean_sepolicy_load"

ensure_state_dir() {
    mkdir -p "$STATE_DIR" 2>/dev/null || return 1
    chmod 0700 "$STATE_DIR" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null || true
    chmod 0600 "$LOG_FILE" 2>/dev/null || true
}

now() {
    date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || date 2>/dev/null || echo unknown
}

log_msg() {
    ensure_state_dir || true
    printf '%s %s\n' "$(now)" "$*" >> "$LOG_FILE"
}

write_status() {
    ensure_state_dir || return 1
    {
        echo "updated=$(now)"
        echo "state=$1"
        echo "detail=${2:-}"
        echo "kernel=$(uname -r 2>/dev/null || true)"
        echo "module_loaded=$(module_is_loaded && echo 1 || echo 0)"
        echo "autoload=$([ -f "$AUTOLOAD_FILE" ] && echo 1 || echo 0)"
        echo "safe_mode=$([ -f "$SAFE_MODE_FILE" ] && echo 1 || echo 0)"
    } > "$STATUS_FILE.tmp" && mv -f "$STATUS_FILE.tmp" "$STATUS_FILE"
    chmod 0600 "$STATUS_FILE" 2>/dev/null || true
}

load_defaults() {
    GUARD_SECONDS=120
    TRIAL_SECONDS=60
    # Consumed by service.sh after this library is sourced.
    # shellcheck disable=SC2034
    BOOT_DELAY_SECONDS=30
    # shellcheck disable=SC2034
    BOOT_WAIT_SECONDS=180
    TRACE_QUERIES=0
    TRACE_LIMIT=16
    [ -r "$MODDIR/config/default.conf" ] && . "$MODDIR/config/default.conf"
    [ -r "$STATE_DIR/config.conf" ] && . "$STATE_DIR/config.conf"
}

module_is_loaded() {
    grep -q '^selhide ' /proc/modules 2>/dev/null
}

sha256_file() {
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

select_module() {
    SELECTED_RELEASE="$(uname -r 2>/dev/null || true)"
    [ -n "$SELECTED_RELEASE" ] || return 20
    [ -r "$MANIFEST" ] || return 21

    SELECTED_LINE="$(awk -F '|' -v release="$SELECTED_RELEASE" '
        $0 !~ /^#/ && $1 == release { print; exit }
    ' "$MANIFEST")"
    [ -n "$SELECTED_LINE" ] || return 22

    SELECTED_RELATIVE="$(printf '%s\n' "$SELECTED_LINE" | cut -d '|' -f 2)"
    SELECTED_SHA256="$(printf '%s\n' "$SELECTED_LINE" | cut -d '|' -f 3)"
    SELECTED_LABEL="$(printf '%s\n' "$SELECTED_LINE" | cut -d '|' -f 4-)"
    SELECTED_KO="$MODDIR/$SELECTED_RELATIVE"
    [ -f "$SELECTED_KO" ] || return 23

    if [ -n "$SELECTED_SHA256" ] && [ "$SELECTED_SHA256" != "-" ]; then
        actual_sha256="$(sha256_file "$SELECTED_KO")"
        [ "$actual_sha256" = "$SELECTED_SHA256" ] || return 24
    fi
    return 0
}

ensure_clean_policy() {
    finder="$MODDIR/bin/find_clean_sepolicy_load.sh"
    [ -x "$finder" ] || return 30
    OUT_DIR="$STATE_DIR" OUT="$POLICY_FILE" \
        REPORT="$STATE_DIR/clean_sepolicy_report.txt" "$finder"
}

detect_setprocattr_cfi_symbol() {
    grep -E -m1 -o 'selinux_setprocattr[^ ]*\.cfi_jt' \
        /proc/kallsyms 2>/dev/null || true
}

run_preflight() {
    ensure_state_dir || return 10
    select_module || {
        rc=$?
        log_msg "preflight module selection failed rc=$rc kernel=$(uname -r 2>/dev/null)"
        write_status incompatible "module-selection-rc-$rc"
        return "$rc"
    }
    [ -x "$LOADER" ] || {
        log_msg "preflight loader missing"
        write_status error loader-missing
        return 25
    }
    ensure_clean_policy || {
        rc=$?
        log_msg "preflight clean policy failed rc=$rc"
        write_status incompatible clean-policy-missing
        return "$rc"
    }

    log_msg "preflight start label=$SELECTED_LABEL ko=$SELECTED_RELATIVE"
    "$LOADER" --check-vermagic "$SELECTED_KO" >> "$LOG_FILE" 2>&1 || {
        rc=$?
        log_msg "preflight vermagic check failed rc=$rc"
        write_status incompatible "vermagic-rc-$rc"
        return "$rc"
    }
    "$LOADER" --dry-run "$SELECTED_KO" >> "$LOG_FILE" 2>&1 || {
        rc=$?
        log_msg "preflight symbol check failed rc=$rc"
        write_status incompatible "symbol-check-rc-$rc"
        return "$rc"
    }
    write_status ready "$SELECTED_LABEL"
    log_msg "preflight passed"
    return 0
}

arm_panic_guard() {
    mode="$1"
    boot_id="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
    guard_nonce="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
    [ -n "$guard_nonce" ] || guard_nonce="$$:$(date +%s 2>/dev/null || echo unknown)"
    ARMED_GUARD_ID="$boot_id:$guard_nonce"
    {
        echo "guard_id=$ARMED_GUARD_ID"
        echo "armed=$(now)"
        echo "boot_id=$boot_id"
        echo "mode=$mode"
        echo "kernel=$(uname -r 2>/dev/null || true)"
        echo "module=$SELECTED_RELATIVE"
        echo "sha256=$SELECTED_SHA256"
    } > "$GUARD_FILE.tmp" && mv -f "$GUARD_FILE.tmp" "$GUARD_FILE"
    chmod 0600 "$GUARD_FILE" 2>/dev/null || true
    sync
    log_msg "panic guard armed mode=$mode"
}

clear_panic_guard() {
    expected_id="${1:-}"
    if [ -n "$expected_id" ]; then
        grep -Fqx "guard_id=$expected_id" "$GUARD_FILE" 2>/dev/null || return 1
    fi
    rm -f "$GUARD_FILE"
    sync
    log_msg "panic guard cleared"
}

start_guard_watcher() {
    seconds="$1"
    expected_guard_id="$2"
    selected_label="$3"
    expected_boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
    (
        sleep "$seconds"
        current_boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
        if [ "$current_boot" = "$expected_boot" ] && module_is_loaded; then
            if clear_panic_guard "$expected_guard_id"; then
                write_status loaded-stable "$selected_label"
            fi
        fi
    ) >/dev/null 2>&1 &
}

load_guarded() {
    mode="${1:-manual}"
    [ ! -f "$SAFE_MODE_FILE" ] || {
        write_status blocked safe-mode
        log_msg "load refused: safe mode active"
        return 40
    }
    module_is_loaded && return 0
    run_preflight || return $?
    if [ "$mode" = "autoload" ] && ! trial_matches_current; then
        log_msg "autoload refused: trial identity does not match current runtime"
        write_status blocked trial-identity-mismatch
        return 60
    fi
    arm_panic_guard "$mode" || return 41
    guard_id="$ARMED_GUARD_ID"

    set -- \
        access_hook=1 \
        clean_access=1 \
        context_hook=1 \
        setprocattr_hook=1 \
        "trace_queries=$TRACE_QUERIES" \
        "trace_limit=$TRACE_LIMIT" \
        "policy_path=$POLICY_FILE"
    cfi_symbol="$(detect_setprocattr_cfi_symbol)"
    [ -z "$cfi_symbol" ] || set -- "$@" "setprocattr_cfi_symbol=$cfi_symbol"

    log_msg "load start mode=$mode"
    "$LOADER" "$SELECTED_KO" "$@" >> "$LOG_FILE" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ] || ! module_is_loaded; then
        log_msg "load failed rc=$rc loaded=$(module_is_loaded && echo 1 || echo 0)"
        clear_panic_guard
        write_status error "load-rc-$rc"
        return "$rc"
    fi

    write_status loaded-guarded "$mode"
    log_msg "load passed; guard window=${GUARD_SECONDS}s"
    start_guard_watcher "$GUARD_SECONDS" "$guard_id" "$SELECTED_LABEL"
    return 0
}

unload_module() {
    if module_is_loaded; then
        rmmod selhide >> "$LOG_FILE" 2>&1 || return $?
    fi
    clear_panic_guard
    write_status unloaded manual
    log_msg "module unloaded"
}

run_trial() {
    seconds="${1:-$TRIAL_SECONDS}"
    case "$seconds" in
        ''|*[!0-9]*) return 50 ;;
    esac
    [ "$seconds" -ge 5 ] || seconds=5
    load_guarded trial || return $?
    log_msg "trial holding for ${seconds}s"
    sleep "$seconds"
    module_is_loaded || return 51
    unload_module || return $?
    record_trial_passed || return $?
    write_status trial-passed "${seconds}s"
    log_msg "trial passed"
}

enable_autoload() {
    run_preflight || return $?
    trial_matches_current || {
        log_msg "autoload refused: no trial for current runtime identity"
        write_status blocked trial-required-for-current-artifact
        return 60
    }
    rm -f "$SAFE_MODE_FILE" "$MODDIR/disable"
    touch "$AUTOLOAD_FILE"
    chmod 0600 "$AUTOLOAD_FILE" 2>/dev/null || true
    write_status autoload-enabled reboot-required
    log_msg "autoload enabled"
}

runtime_identity() {
    select_module || return $?
    [ -x "$LOADER" ] || return 25
    [ -r "$POLICY_FILE" ] || return 30
    IDENTITY_KERNEL="$SELECTED_RELEASE"
    IDENTITY_MODULE_SHA256="$(sha256_file "$SELECTED_KO")"
    IDENTITY_LOADER_SHA256="$(sha256_file "$LOADER")"
    IDENTITY_POLICY_SHA256="$(sha256_file "$POLICY_FILE")"
    [ -n "$IDENTITY_MODULE_SHA256" ] || return 71
    [ -n "$IDENTITY_LOADER_SHA256" ] || return 72
    [ -n "$IDENTITY_POLICY_SHA256" ] || return 73
}

record_trial_passed() {
    runtime_identity || return $?
    {
        echo "version=1"
        echo "passed=$(now)"
        echo "kernel=$IDENTITY_KERNEL"
        echo "module_sha256=$IDENTITY_MODULE_SHA256"
        echo "loader_sha256=$IDENTITY_LOADER_SHA256"
        echo "policy_sha256=$IDENTITY_POLICY_SHA256"
    } > "$TRIAL_PASSED_FILE.tmp" &&
        mv -f "$TRIAL_PASSED_FILE.tmp" "$TRIAL_PASSED_FILE"
    chmod 0600 "$TRIAL_PASSED_FILE" 2>/dev/null || true
    sync
}

trial_matches_current() {
    [ -r "$TRIAL_PASSED_FILE" ] || return 1
    runtime_identity || return $?
    grep -Fqx "version=1" "$TRIAL_PASSED_FILE" 2>/dev/null &&
        grep -Fqx "kernel=$IDENTITY_KERNEL" "$TRIAL_PASSED_FILE" 2>/dev/null &&
        grep -Fqx "module_sha256=$IDENTITY_MODULE_SHA256" "$TRIAL_PASSED_FILE" 2>/dev/null &&
        grep -Fqx "loader_sha256=$IDENTITY_LOADER_SHA256" "$TRIAL_PASSED_FILE" 2>/dev/null &&
        grep -Fqx "policy_sha256=$IDENTITY_POLICY_SHA256" "$TRIAL_PASSED_FILE" 2>/dev/null
}

disable_autoload() {
    rm -f "$AUTOLOAD_FILE"
    write_status autoload-disabled manual
    log_msg "autoload disabled"
}

import_magisk_denylist() {
    ensure_state_dir || return 1
    if command -v magisk >/dev/null 2>&1; then
        magisk --denylist ls 2>/dev/null | sort -u > "$APPLY_LIST_FILE.tmp"
    elif [ -x /data/adb/magisk/magisk ]; then
        /data/adb/magisk/magisk --denylist ls 2>/dev/null | sort -u > "$APPLY_LIST_FILE.tmp"
    else
        return 70
    fi
    mv -f "$APPLY_LIST_FILE.tmp" "$APPLY_LIST_FILE"
    chmod 0600 "$APPLY_LIST_FILE" 2>/dev/null || true
    log_msg "denylist imported entries=$(wc -l < "$APPLY_LIST_FILE" 2>/dev/null)"
    echo "NOTE: apply-list is metadata only; per-app LKM enforcement is not implemented yet."
}

recover_from_pending_guard() {
    [ -f "$GUARD_FILE" ] || return 1
    ensure_state_dir || return 1
    stamp="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo unknown)"
    cp -f "$GUARD_FILE" "$STATE_DIR/recovered_guard_$stamp.txt" 2>/dev/null || true
    evidence_dir="$STATE_DIR/recovery_$stamp"
    mkdir -p "$evidence_dir" 2>/dev/null || true
    chmod 0700 "$evidence_dir" 2>/dev/null || true
    if [ -d /sys/fs/pstore ]; then
        for entry in /sys/fs/pstore/*; do
            [ -f "$entry" ] || continue
            cp -f "$entry" "$evidence_dir/" 2>/dev/null || true
        done
    fi
    {
        echo "recovered=$(now)"
        uname -a 2>/dev/null || true
        getprop ro.product.device 2>/dev/null || true
        getprop ro.build.fingerprint 2>/dev/null || true
    } > "$evidence_dir/device.txt" 2>/dev/null || true
    rm -f "$AUTOLOAD_FILE"
    touch "$SAFE_MODE_FILE" "$MODDIR/disable"
    rm -f "$GUARD_FILE"
    sync
    log_msg "uncleared panic guard detected; module self-disabled"
    write_status self-disabled uncleared-panic-guard
    return 0
}
