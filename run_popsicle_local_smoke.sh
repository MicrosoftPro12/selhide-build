#!/system/bin/sh
# One-click local smoke test for popsicle Android 16 / 6.12.
#
# Default behavior:
# - writes output to the current directory
# - finds the local p0.13 selhide ko, kallsyms loader, and clean Magisk policy
# - runs one conservative load/probe/unload cycle
#
# Optional environment overrides:
#   KO=/path/to/selhide.ko
#   LOADER=/path/to/kallsyms_init_module
#   POLICY_PATH=/path/to/clean/load

case "$0" in
    */*) SCRIPT_DIR="${0%/*}" ;;
    *) SCRIPT_DIR="." ;;
esac
cd "$SCRIPT_DIR" 2>/dev/null || true

pick_file() {
    for p in "$@"; do
        [ -n "$p" ] || continue
        [ -f "$p" ] || continue
        echo "$p"
        return 0
    done
    return 1
}

pick_exec() {
    for p in "$@"; do
        [ -n "$p" ] || continue
        [ -f "$p" ] || continue
        [ -x "$p" ] || chmod 755 "$p" 2>/dev/null || true
        [ -x "$p" ] || continue
        echo "$p"
        return 0
    done
    return 1
}

KO="${KO:-$(pick_file \
    ./selhide-android16-6.12.ko \
    ./selhide-popsicle-android16-6.12-dsp2-exp.ko \
    ./selhide-popsicle/selhide.ko \
    /workdir/selhide-build/selhide-popsicle/selhide.ko \
    /workdir/out-popsicle-6.12-exp-v2/selhide-popsicle-android16-6.12-dsp2-exp.ko \
    /workdir/out-popsicle-6.12-exp-v2-new/selhide-popsicle-android16-6.12-dsp2-exp.ko \
    /workdir/selhide-android16-6.12.ko \
    2>/dev/null || true)}"

LOADER="${LOADER:-$(pick_exec \
    ./kallsyms_init_module \
    /workdir/kallsyms_init_module \
    ./out-popsicle-6.12-exp-v2/kallsyms_init_module \
    /workdir/out-popsicle-6.12-exp-v2/kallsyms_init_module \
    2>/dev/null || true)}"

POLICY_PATH="${POLICY_PATH:-$(pick_file \
    /debug_ramdisk/.magisk/selinux/load \
    ./load \
    /workdir/load \
    ./out-popsicle-6.12-exp-v2/load \
    /workdir/out-popsicle-6.12-exp-v2/load \
    2>/dev/null || true)}"

TEST_SH="${TEST_SH:-$(pick_file \
    ./test_selhide_dirtysepolicy2_popsicle.sh \
    /workdir/selhide-build/test_selhide_dirtysepolicy2_popsicle.sh \
    2>/dev/null || true)}"

OUT="${OUT:-./test_artifact_local_smoke_$(date +%Y%m%d_%H%M%S).txt}"

if [ -z "$KO" ] || [ -z "$LOADER" ] || [ -z "$POLICY_PATH" ] || [ -z "$TEST_SH" ]; then
    {
        echo "ERROR: missing test input"
        echo "ko=$KO"
        echo "loader=$LOADER"
        echo "policy_path=$POLICY_PATH"
        echo "test_sh=$TEST_SH"
        echo "pwd=$(pwd)"
        echo "hint: put selhide-android16-6.12.ko, kallsyms_init_module, and load in this directory, or run from /workdir/selhide-build."
    } > "$OUT" 2>&1
    echo "$OUT"
    exit 2
fi

KO="$KO" \
LOADER="$LOADER" \
POLICY_PATH="$POLICY_PATH" \
RUN_APP="${RUN_APP:-0}" \
RUN_PROBES="${RUN_PROBES:-1}" \
AUTO_RMMOD="${AUTO_RMMOD:-1}" \
OUT="$OUT" \
sh "$TEST_SH"
exit $?
