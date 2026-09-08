#!/system/bin/sh

MODDIR=${0%/*}
. "$MODDIR/common/selhide_common.sh"

if module_is_loaded; then
    rmmod selhide 2>/dev/null || true
fi
rm -f "$AUTOLOAD_FILE" "$GUARD_FILE" "$TRIAL_PASSED_FILE"
log_msg "module package uninstalled; diagnostic state preserved"
