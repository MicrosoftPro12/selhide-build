#!/system/bin/sh
# One-click conservative stress run: 3 rounds with DirtySepolicy APK launch.

case "$0" in
    */*) SCRIPT_DIR="${0%/*}" ;;
    *) SCRIPT_DIR="." ;;
esac
cd "$SCRIPT_DIR" 2>/dev/null || true

ROUNDS="${ROUNDS:-3}" \
ROUND_PROBES="${ROUND_PROBES:-1}" \
RUN_APP="${RUN_APP:-1}" \
sh ./stress_selhide_dirtysepolicy2_popsicle.sh
