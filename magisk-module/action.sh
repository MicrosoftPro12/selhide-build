#!/system/bin/sh

MODDIR=${0%/*}

echo "SelHide safe status/preflight"
"$MODDIR/bin/selhide_ctl.sh" status
echo
echo "Running load-free preflight..."
"$MODDIR/bin/selhide_ctl.sh" preflight
rc=$?
echo "preflight_exit=$rc"
echo "No kernel module was loaded. Use selhide_ctl.sh trial explicitly."
exit "$rc"
