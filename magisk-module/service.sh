#!/system/bin/sh

MODDIR=${0%/*}
. "$MODDIR/common/selhide_common.sh"

load_defaults
ensure_state_dir || exit 1
[ ! -f "$MODDIR/disable" ] || exit 0
[ ! -f "$SAFE_MODE_FILE" ] || exit 0
[ -f "$AUTOLOAD_FILE" ] || {
    write_status installed manual-trial-required
    exit 0
}

# Keep the risky operation out of blocking post-fs-data and wait for Android to
# become usable before loading a previously validated artifact.
case "$BOOT_WAIT_SECONDS" in
    ''|*[!0-9]*) BOOT_WAIT_SECONDS=180 ;;
esac
i=0
while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ] && [ "$i" -lt "$BOOT_WAIT_SECONDS" ]; do
    sleep 1
    i=$((i + 1))
done
[ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] || {
    write_status autoload-deferred boot-not-complete
    log_msg "autoload skipped: Android did not complete boot"
    exit 0
}

case "$BOOT_DELAY_SECONDS" in
    ''|*[!0-9]*) BOOT_DELAY_SECONDS=30 ;;
esac
[ "$BOOT_DELAY_SECONDS" -eq 0 ] || sleep "$BOOT_DELAY_SECONDS"

load_guarded autoload || {
    rc=$?
    rm -f "$AUTOLOAD_FILE"
    touch "$SAFE_MODE_FILE"
    write_status autoload-failed "rc-$rc"
    log_msg "autoload failed rc=$rc; safe mode armed"
}
