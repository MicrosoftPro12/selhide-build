#!/system/bin/sh

MODDIR=${0%/*}
. "$MODDIR/common/selhide_common.sh"

load_defaults
ensure_state_dir || {
    echo "ERROR: cannot create $STATE_DIR"
    exit 10
}
trap 'cleanup_volume_key_listener' EXIT INT TERM

echo "SelHide guarded Action"
sh "$MODDIR/bin/selhide_ctl.sh" status
echo

read_action_key() {
    wait_volume_key "$ACTION_KEY_TIMEOUT_SECONDS"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        if [ "$rc" -eq 1 ]; then
            echo "No volume key received within ${ACTION_KEY_TIMEOUT_SECONDS}s. No change made."
        else
            echo "Volume-key input is unavailable. No change made."
        fi
        return "$rc"
    fi
    action_key="$VOLUME_KEY_RESULT"
    return 0
}

# Once enabled, Action offers an emergency off path. Disable autoload before
# attempting rmmod so a failed unload cannot silently remain persistent.
if [ -f "$AUTOLOAD_FILE" ] || module_is_loaded; then
    action_hiding_runtime="$(runtime_hiding_state)"
    action_hiding_desired="$(desired_hiding_state)"
    if [ "$action_hiding_runtime" = "active" ] ||
        { [ "$action_hiding_runtime" = "unloaded" ] && [ "$action_hiding_desired" = "active" ]; }; then
        echo "Volume UP: pause hiding without unloading"
    else
        echo "Volume UP: resume hiding without reloading"
    fi
    echo "Volume DOWN: disable autoload and unload SelHide"
    read_action_key || exit 0
    if [ "$action_key" = "up" ]; then
        toggle_runtime_hiding || {
            rc=$?
            echo "ERROR: hiding state change failed (rc=$rc)."
            exit "$rc"
        }
        echo "SelHide runtime mode updated."
        exit 0
    fi
    echo "Disabling autoload..."
    disable_autoload || exit $?
    if module_is_loaded; then
        echo "Unloading SelHide..."
        unload_module || {
            rc=$?
            echo "ERROR: unload failed (rc=$rc); autoload remains disabled."
            exit "$rc"
        }
    fi
    echo "SelHide is OFF."
    exit 0
fi

if [ -f "$SAFE_MODE_FILE" ]; then
    latest_record=""
    for record in "$STATE_DIR"/recovered_guard_*.txt; do
        [ -f "$record" ] || continue
        latest_record="$record"
    done
    recovered_sha=""
    [ -z "$latest_record" ] || recovered_sha="$(awk -F= '$1 == "sha256" { print $2; exit }' "$latest_record")"
    current_sha=""
    select_module >/dev/null 2>&1 && current_sha="$SELECTED_SHA256"

    echo "BLOCKED: persistent safe mode is active."
    if [ -n "$recovered_sha" ] && [ "$recovered_sha" = "$current_sha" ]; then
        echo "The current artifact is the same one associated with the uncleared panic guard."
    fi
    [ -z "$latest_record" ] || echo "Recovery record: $latest_record"
    echo "Inspect recovery evidence before clearing safe mode explicitly."
    exit 40
fi

echo "Running load-free preflight..."
run_preflight
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "ERROR: preflight failed (rc=$rc). Nothing was loaded."
    exit "$rc"
fi
echo "Preflight passed."
echo

if trial_matches_current; then
    echo "The current kernel/module/loader/policy identity already passed trial."
    echo "Volume UP: enable boot autoload"
    echo "Volume DOWN: cancel"
    read_action_key || exit 0
    if [ "$action_key" != "up" ]; then
        echo "Canceled. Autoload remains OFF."
        exit 0
    fi
    echo "Enabling boot autoload..."
    enable_autoload || {
        rc=$?
        echo "ERROR: could not enable autoload (rc=$rc)."
        exit "$rc"
    }
    echo "Autoload is ON. Reboot to test guarded boot loading."
    echo "Tap Action again at any time to turn it off."
    exit 0
fi

echo "Volume UP: start the guarded trial"
echo "Volume DOWN: cancel without loading"
read_action_key || exit 0
if [ "$action_key" != "up" ]; then
    echo "Canceled. Nothing was loaded."
    exit 0
fi

echo "Starting a guarded ${TRIAL_SECONDS}s trial."
echo "Keep this Action open and run DirtySepolicy during the trial window."
run_trial "$TRIAL_SECONDS"
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "ERROR: trial did not complete (rc=$rc). Autoload was not enabled."
    exit "$rc"
fi

echo "Trial passed and SelHide unloaded cleanly."
echo "Open Action again and press Volume UP to enable boot autoload."
