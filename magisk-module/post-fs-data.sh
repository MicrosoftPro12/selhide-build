#!/system/bin/sh

MODDIR=${0%/*}
. "$MODDIR/common/selhide_common.sh"

# A marker can survive only if the previous guarded load did not reach its
# stability checkpoint, most importantly when init_module caused a panic.
recover_from_pending_guard >/dev/null 2>&1 || true
