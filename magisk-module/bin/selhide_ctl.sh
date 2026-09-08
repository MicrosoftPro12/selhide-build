#!/system/bin/sh

MODDIR="${0%/*}/.."
. "$MODDIR/common/selhide_common.sh"

load_defaults
ensure_state_dir || exit 10

usage() {
    cat <<'EOF'
Usage: selhide_ctl.sh COMMAND [ARG]

Commands:
  status             Show current module and guard state
  preflight          Verify exact kernel artifact, policy and symbols; no load
  trial [seconds]    Guarded temporary load, then unload and mark trial passed
  load               Guarded load; clear guard after the stability window
  unload             Unload selhide and clear the guard
  enable-autoload    Enable boot load after a successful trial
  disable-autoload   Disable boot load without disabling the Magisk module
  import-denylist    Save Magisk denylist as apply-list metadata
  clear-safe-mode    Clear recovery state; does not enable autoload
  diagnose           Write a reusable diagnostic report
EOF
}

show_status() {
    echo "kernel=$(uname -r 2>/dev/null || true)"
    echo "module_loaded=$(module_is_loaded && echo 1 || echo 0)"
    echo "magisk_module_disabled=$([ -f "$MODDIR/disable" ] && echo 1 || echo 0)"
    echo "safe_mode=$([ -f "$SAFE_MODE_FILE" ] && echo 1 || echo 0)"
    echo "panic_guard=$([ -f "$GUARD_FILE" ] && echo 1 || echo 0)"
    echo "trial_passed=$([ -f "$TRIAL_PASSED_FILE" ] && echo 1 || echo 0)"
    echo "trial_current=$(trial_matches_current && echo 1 || echo 0)"
    echo "autoload=$([ -f "$AUTOLOAD_FILE" ] && echo 1 || echo 0)"
    if select_module; then
        echo "artifact=$SELECTED_RELATIVE"
        echo "artifact_label=$SELECTED_LABEL"
        echo "artifact_sha256=$SELECTED_SHA256"
    else
        echo "artifact=none"
    fi
    [ ! -r "$STATUS_FILE" ] || cat "$STATUS_FILE"
}

diagnose() {
    stamp="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo unknown)"
    out="$STATE_DIR/diagnose_$stamp.txt"
    {
        echo "selhide diagnostic"
        echo "date=$(now)"
        uname -a
        getprop ro.product.device 2>/dev/null || true
        getprop ro.build.version.release 2>/dev/null || true
        show_status
        echo
        echo "== manifest match =="
        grep -F "$(uname -r)|" "$MANIFEST" 2>/dev/null || true
        echo
        echo "== policy =="
        ls -l "$POLICY_FILE" "$STATE_DIR/clean_sepolicy_report.txt" 2>/dev/null || true
        echo
        echo "== pstore =="
        ls -la /sys/fs/pstore 2>/dev/null || true
        echo
        echo "== recent kernel log =="
        dmesg 2>/dev/null | grep -iE 'selhide|panic|oops|cfi|kcfi|bti|setprocattr|SEL_ACCESS|SEL_CONTEXT' | tail -n 400
    } > "$out"
    chmod 0600 "$out" 2>/dev/null || true
    echo "$out"
}

case "${1:-status}" in
    status) show_status ;;
    preflight) run_preflight ;;
    trial) run_trial "${2:-$TRIAL_SECONDS}" ;;
    load) load_guarded manual ;;
    unload) unload_module ;;
    enable-autoload) enable_autoload ;;
    disable-autoload) disable_autoload ;;
    import-denylist) import_magisk_denylist ;;
    clear-safe-mode)
        rm -f "$SAFE_MODE_FILE" "$GUARD_FILE"
        write_status safe-mode-cleared manual
        ;;
    diagnose) diagnose ;;
    *) usage; exit 2 ;;
esac
