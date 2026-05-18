#!/system/bin/sh
# Summarize selhide DirtySepolicy 2.x one-shot/stress logs.
# Output is written to the current directory unless OUT is set.

case "$0" in
    */*) SCRIPT_DIR="${0%/*}" ;;
    *) SCRIPT_DIR="." ;;
esac
cd "$SCRIPT_DIR" 2>/dev/null || true

OUT="${OUT:-./selhide_dirtysepolicy2_summary_$(date +%Y%m%d_%H%M%S).txt}"
FATAL_RE='FPAC|Oops|panic|Kernel panic|Internal error|Unable to handle|BUG:|Call trace:|------------\[ cut here \]------------'

if [ "$#" -gt 0 ]; then
    LOGS="$*"
else
    LOGS="$(ls -t ./test_selhide_dirtysepolicy2_popsicle_*.txt ./stress_round_*.txt 2>/dev/null || true)"
fi

hash_file() {
    file="$1"
    if [ -f "$file" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$file"
        elif command -v toybox >/dev/null 2>&1; then
            toybox sha256sum "$file"
        else
            echo "SKIP sha256 $file"
        fi
    fi
}

summarize_one() {
    f="$1"
    [ -f "$f" ] || return 0
    base="${f##*/}"
    dry="$(grep -c 'dry_run_exit=0' "$f")"
    load="$(grep -c 'load_exit=0' "$f")"
    rmmod="$(grep -c 'rmmod_exit=0' "$f")"
    success="$(grep -c 'phase0 success' "$f")"
    hidden_context="$(grep -c 'SEL_CONTEXT hidden dirty context' "$f")"
    hidden_setprocattr="$(grep -c 'setprocattr current hidden dirty context' "$f")"
    restored="$(grep -c 'hook restored' "$f")"
    fatal="$(grep -Ei "$FATAL_RE" "$f" | wc -l | tr -d ' ')"
    errors="$(grep -E 'ERROR:|load_exit=[1-9]|rmmod_exit=[1-9]|dry_run_exit=[1-9]' "$f" | wc -l | tr -d ' ')"

    verdict="PASS"
    if [ "$dry" = "0" ] || [ "$load" = "0" ] || [ "$rmmod" = "0" ] || [ "$success" = "0" ] || [ "$fatal" != "0" ] || [ "$errors" != "0" ]; then
        verdict="CHECK"
    fi

    printf '%s verdict=%s dry=%s load=%s rmmod=%s success=%s hidden_context=%s hidden_setprocattr=%s restored=%s fatal=%s errors=%s\n' \
        "$base" "$verdict" "$dry" "$load" "$rmmod" "$success" "$hidden_context" "$hidden_setprocattr" "$restored" "$fatal" "$errors"
}

{
    echo "selhide DirtySepolicy 2.x summary"
    date
    uname -a 2>/dev/null || true
    echo
    echo "== artifacts =="
    hash_file ./selhide-popsicle-android16-6.12-dsp2-exp.ko
    hash_file ./selhide-android16-6.12.ko
    hash_file ./kallsyms_init_module
    hash_file ./load

    echo
    echo "== logs =="
    if [ -z "$LOGS" ]; then
        echo "NO_LOGS"
    else
        for f in $LOGS; do
            summarize_one "$f"
        done
    fi
} > "$OUT"

cat "$OUT"
exit 0
