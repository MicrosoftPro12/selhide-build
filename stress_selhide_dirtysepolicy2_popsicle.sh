#!/system/bin/sh
# Repeated load/probe/unload stress runner for popsicle DirtySepolicy 2.x work.
# Writes a single summary log into the current directory.

case "$0" in
    */*) SCRIPT_DIR="${0%/*}" ;;
    *) SCRIPT_DIR="." ;;
esac
cd "$SCRIPT_DIR" 2>/dev/null || true

ROUNDS="${ROUNDS:-5}"
ROUND_PROBES="${ROUND_PROBES:-1}"
RUN_APP="${RUN_APP:-0}"
OUT="${OUT:-./stress_selhide_dirtysepolicy2_popsicle_$(date +%Y%m%d_%H%M%S).txt}"
TEST_SH="${TEST_SH:-./test_selhide_dirtysepolicy2_popsicle.sh}"
SUMMARY_SH="${SUMMARY_SH:-./summarize_selhide_dirtysepolicy2_logs.sh}"
FATAL_RE='FPAC|Oops|panic|Kernel panic|Internal error|Unable to handle|BUG:|Call trace:|------------\[ cut here \]------------'

log_section() {
    echo
    echo "== $* =="
}

main() {
    pass=0
    fail=0
    i=1

    log_section meta
    date
    uname -a
    id
    echo "rounds=$ROUNDS"
    echo "round_probes=$ROUND_PROBES"
    echo "run_app=$RUN_APP"
    echo "test_sh=$TEST_SH"

    if [ ! -f "$TEST_SH" ]; then
        echo "ERROR: missing test script: $TEST_SH"
        return 2
    fi

    while [ "$i" -le "$ROUNDS" ]; do
        round_out="./stress_round_${i}_$(date +%Y%m%d_%H%M%S).txt"
        log_section "round_$i"
        echo "round_log=$round_out"
        OUT="$round_out" RUN_PROBES="$ROUND_PROBES" RUN_APP="$RUN_APP" sh "$TEST_SH"
        rc=$?
        echo "round_exit=$rc"

        fatal_hits="$(grep -Ei "$FATAL_RE" "$round_out" | wc -l | tr -d ' ')"

        if [ "$rc" = "0" ] &&
            grep -q 'dry_run_exit=0' "$round_out" &&
            grep -q 'load_exit=0' "$round_out" &&
            grep -q 'rmmod_exit=0' "$round_out" &&
            grep -q 'phase0 success' "$round_out" &&
            grep -q 'setprocattr clean hook installed' "$round_out" &&
            grep -q 'SEL_CONTEXT clean hook installed' "$round_out" &&
            grep -q 'SEL_ACCESS passthrough hook installed' "$round_out" &&
            grep -q 'setprocattr hook restored' "$round_out" &&
            grep -q 'SEL_CONTEXT hook restored' "$round_out" &&
            grep -q 'SEL_ACCESS hook restored' "$round_out" &&
            [ "$fatal_hits" = "0" ]
        then
            echo "round_verdict=PASS"
            pass=$((pass + 1))
        else
            echo "round_verdict=FAIL"
            fail=$((fail + 1))
        fi

        echo "fatal_hits=$fatal_hits"
        grep -Ei "dry_run_exit=|load_exit=|rmmod_exit=|RESULT:|ERROR:|WARN:|$FATAL_RE" "$round_out" || true
        i=$((i + 1))
        sleep 1
    done

    log_section summary
    echo "pass=$pass"
    echo "fail=$fail"
    if [ -f "$SUMMARY_SH" ]; then
        sh "$SUMMARY_SH" ./stress_round_*.txt || true
    fi

    [ "$fail" = "0" ]
}

main > "$OUT" 2>&1
rc=$?
echo "$OUT"
exit "$rc"
