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
  hiding-on          Enable clean-policy responses now and on future loads
  hiding-off         Pause hiding; hooks stay loaded in passthrough mode
  toggle-hiding      Toggle active/passthrough without unloading
  enable-autoload    Enable boot load after a successful trial
  disable-autoload   Disable boot load without disabling the Magisk module
  shutdown           Disable autoload and unload the LKM
  web-status         Print stable key=value status for WebUI clients
  apply-list         Print selected packages and resolved appIds
  apply-mode-sync    Continuously mirror the Magisk denylist (read-only)
  apply-mode-manual  Snapshot the Magisk denylist and unlock editing
  apply-sync-now     Refresh immediately while in sync mode
  apply-add PACKAGE  Add a package in manual mode
  apply-remove PKG   Remove a package in manual mode
  apply-clear        Clear the package list in manual mode
  import-denylist    Alias for apply-mode-manual
  clear-safe-mode    Clear recovery state; does not enable autoload
  diagnose           Write a reusable diagnostic report
EOF
}

show_status() {
    echo "kernel=$(uname -r 2>/dev/null || true)"
    echo "module_loaded=$(module_is_loaded && echo 1 || echo 0)"
    echo "hiding_runtime=$(runtime_hiding_state)"
    echo "hiding_desired=$(desired_hiding_state)"
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

show_web_status() {
    echo "protocol=1"
    echo "kernel=$(uname -r 2>/dev/null || true)"
    echo "module_loaded=$(module_is_loaded && echo 1 || echo 0)"
    echo "hiding_runtime=$(runtime_hiding_state)"
    echo "hiding_desired=$(desired_hiding_state)"
    echo "autoload=$([ -f "$AUTOLOAD_FILE" ] && echo 1 || echo 0)"
    echo "safe_mode=$([ -f "$SAFE_MODE_FILE" ] && echo 1 || echo 0)"
    echo "panic_guard=$([ -f "$GUARD_FILE" ] && echo 1 || echo 0)"
    echo "trial_current=$(trial_matches_current && echo 1 || echo 0)"
    echo "trial_seconds=$TRIAL_SECONDS"
    echo "module_disabled=$([ -f "$MODDIR/disable" ] && echo 1 || echo 0)"
    echo "apply_mode=$(apply_list_mode)"
    echo "apply_packages=$(apply_packages_csv)"
    echo "apply_appids=$(apply_appids_csv)"
    echo "last_state=$(awk -F= '$1 == "state" { print $2; exit }' "$STATUS_FILE" 2>/dev/null)"
    echo "last_detail=$(awk -F= '$1 == "detail" { print $2; exit }' "$STATUS_FILE" 2>/dev/null)"
}

show_apply_list() {
    echo "apply_mode=$(apply_list_mode)"
    echo "apply_packages=$(apply_packages_csv)"
    echo "apply_appids=$(apply_appids_csv)"
}

shutdown_selhide() {
    disable_autoload || return $?
    unload_module
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
    hiding-on) set_runtime_hiding 1 ;;
    hiding-off) set_runtime_hiding 0 ;;
    toggle-hiding) toggle_runtime_hiding ;;
    enable-autoload) enable_autoload ;;
    disable-autoload) disable_autoload ;;
    shutdown) shutdown_selhide ;;
    web-status) show_web_status ;;
    apply-list) show_apply_list ;;
    apply-mode-sync) [ "$#" -eq 1 ] || exit 2; set_apply_list_mode sync ;;
    apply-mode-manual) [ "$#" -eq 1 ] || exit 2; set_apply_list_mode manual ;;
    apply-sync-now)
        [ "$#" -eq 1 ] || exit 2
        [ "$(apply_list_mode)" = sync ] || exit 96
        refresh_apply_list_from_magisk
        ;;
    apply-add) [ "$#" -eq 2 ] || exit 2; add_apply_package "$2" ;;
    apply-remove) [ "$#" -eq 2 ] || exit 2; remove_apply_package "$2" ;;
    apply-clear) [ "$#" -eq 1 ] || exit 2; clear_apply_list ;;
    import-denylist) import_magisk_denylist ;;
    clear-safe-mode)
        rm -f "$SAFE_MODE_FILE" "$GUARD_FILE"
        write_status safe-mode-cleared manual
        ;;
    diagnose) diagnose ;;
    *) usage; exit 2 ;;
esac
