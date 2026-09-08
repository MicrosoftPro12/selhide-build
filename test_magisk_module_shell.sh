#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
MODULE_ROOT="$ROOT/magisk-module"
ZIP_PATH="${1:-}"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

for file in "$MODULE_ROOT"/*.sh "$MODULE_ROOT"/bin/*.sh "$MODULE_ROOT"/common/*.sh; do
    sh -n "$file"
done

# Keep policy text detection compatible with Android's basic grep parser.
printf '%s\n' '(type test_type)' | grep -qa \
    -e '^(type ' -e '^(allow ' -e '^#' -e '^type ' -e '^allow ' ||
    fail "portable CIL detection pattern did not match"

test_root="$(mktemp -d "${TMPDIR:-/tmp}/selhide-shell-test.XXXXXX")"
state="$(mktemp -d "${TMPDIR:-/tmp}/selhide-state-test.XXXXXX")"
cp -a "$MODULE_ROOT/." "$test_root/"

# Simulate a marker left behind by a panic and verify next-boot recovery.
printf '%s\n' 'guard_id=test-guard' 'mode=trial' 'kernel=test-kernel' > "$state/load_pending"
touch "$state/autoload"
SELHIDE_STATE_DIR="$state" sh "$test_root/post-fs-data.sh"
[ -f "$test_root/disable" ] || fail "Magisk disable marker was not created"
[ -f "$state/safe_mode" ] || fail "safe mode was not created"
[ ! -e "$state/autoload" ] || fail "autoload survived panic recovery"
[ ! -e "$state/load_pending" ] || fail "panic guard was not consumed"
find "$state" -maxdepth 1 -name 'recovered_guard_*.txt' | grep -q . ||
    fail "recovery record was not preserved"
find "$state" -maxdepth 2 -path '*/recovery_*/device.txt' | grep -q . ||
    fail "recovery evidence directory was not created"

# A device that has not completed boot must never reach the loader path.
boot_root="$(mktemp -d "${TMPDIR:-/tmp}/selhide-boot-test.XXXXXX")"
boot_state="$(mktemp -d "${TMPDIR:-/tmp}/selhide-boot-state.XXXXXX")"
cp -a "$MODULE_ROOT/." "$boot_root/"
mkdir -p "$boot_state"
touch "$boot_state/autoload"
printf '%s\n' 'BOOT_WAIT_SECONDS=0' 'BOOT_DELAY_SECONDS=0' > "$boot_state/config.conf"
SELHIDE_STATE_DIR="$boot_state" sh "$boot_root/service.sh"
grep -Fqx 'state=autoload-deferred' "$boot_state/status.env" ||
    fail "incomplete boot did not defer autoload"
[ ! -e "$boot_state/load_pending" ] || fail "incomplete boot armed a panic guard"

# Exercise identity binding without invoking the loader or loading a module.
identity_root="$(mktemp -d "${TMPDIR:-/tmp}/selhide-identity-test.XXXXXX")"
identity_state="$(mktemp -d "${TMPDIR:-/tmp}/selhide-identity-state.XXXXXX")"
cp -a "$MODULE_ROOT/." "$identity_root/"
mkdir -p "$identity_root/bin" "$identity_root/payload/modules/test" "$identity_state"
printf '%s\n' loader > "$identity_root/bin/kallsyms_init_module"
chmod 0755 "$identity_root/bin/kallsyms_init_module"
printf '%s\n' module > "$identity_root/payload/modules/test/selhide.ko"
printf '%s\n' policy > "$identity_state/clean_sepolicy_load"
release="$(uname -r)"
module_sha="$(sha256sum "$identity_root/payload/modules/test/selhide.ko" | awk '{print $1}')"
printf '%s\n' \
    '# exact_kernel_release|relative_module_path|sha256|label' \
    "$release|payload/modules/test/selhide.ko|$module_sha|test" \
    > "$identity_root/payload/manifest.tsv"

MODDIR="$identity_root"
SELHIDE_STATE_DIR="$identity_state"
export MODDIR SELHIDE_STATE_DIR
. "$identity_root/common/selhide_common.sh"
ensure_state_dir
record_trial_passed
trial_matches_current || fail "fresh trial identity did not match"
printf '%s\n' changed-policy > "$identity_state/clean_sepolicy_load"
if trial_matches_current; then
    fail "policy change did not invalidate trial identity"
fi

# A stale watcher ID must never clear a newer panic marker.
select_module
arm_panic_guard first
first_guard="$ARMED_GUARD_ID"
arm_panic_guard second
second_guard="$ARMED_GUARD_ID"
[ "$first_guard" != "$second_guard" ] || fail "guard IDs were reused"
if clear_panic_guard "$first_guard"; then
    fail "stale guard ID cleared a newer marker"
fi
[ -f "$GUARD_FILE" ] || fail "newer panic marker disappeared"
clear_panic_guard "$second_guard"
[ ! -e "$GUARD_FILE" ] || fail "current guard ID was not cleared"

# Exercise the Magisk Action state machine with an isolated module table and
# fake loader. No host kernel operation is performed by this test.
action_root="$(mktemp -d "${TMPDIR:-/tmp}/selhide-action-test.XXXXXX")"
action_state="$(mktemp -d "${TMPDIR:-/tmp}/selhide-action-state.XXXXXX")"
action_bin="$(mktemp -d "${TMPDIR:-/tmp}/selhide-action-bin.XXXXXX")"
action_modules="$action_state/proc_modules"
cp -a "$MODULE_ROOT/." "$action_root/"
mkdir -p "$action_root/payload/modules/test" "$action_root/bin"
printf '%s\n' module > "$action_root/payload/modules/test/selhide.ko"
action_module_sha="$(sha256sum "$action_root/payload/modules/test/selhide.ko" | awk '{print $1}')"
printf '%s\n' \
    '# exact_kernel_release|relative_module_path|sha256|label' \
    "$(uname -r)|payload/modules/test/selhide.ko|$action_module_sha|action-test" \
    > "$action_root/payload/manifest.tsv"
: > "$action_modules"
cat > "$action_root/bin/find_clean_sepolicy_load.sh" <<'EOF'
#!/bin/sh
printf '%s\n' clean-policy > "$OUT"
printf '%s\n' selected=test > "$REPORT"
EOF
cat > "$action_root/bin/kallsyms_init_module" <<'EOF'
#!/bin/sh
case "${1:-}" in
    --check-vermagic|--dry-run) exit 0 ;;
esac
printf '%s\n' 'selhide 1 0 - Live 0x0' > "$SELHIDE_PROC_MODULES"
EOF
cat > "$action_bin/rmmod" <<'EOF'
#!/bin/sh
: > "$SELHIDE_PROC_MODULES"
EOF
cat > "$action_bin/sleep" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$action_bin/getevent" <<'EOF'
#!/bin/sh
case "$(cat "$SELHIDE_ACTION_KEY_FILE" 2>/dev/null)" in
    up) echo '/dev/input/event0: EV_KEY KEY_VOLUMEUP DOWN' ;;
    down) echo '/dev/input/event0: EV_KEY KEY_VOLUMEDOWN DOWN' ;;
esac
EOF
chmod 0755 "$action_root/bin/find_clean_sepolicy_load.sh" \
    "$action_root/bin/kallsyms_init_module" "$action_bin/rmmod" \
    "$action_bin/sleep" "$action_bin/getevent"
printf '%s\n' 'GUARD_SECONDS=5' 'TRIAL_SECONDS=5' > "$action_state/config.conf"

run_action() {
    printf '%s\n' "$1" > "$action_state/action.key"
    SELHIDE_STATE_DIR="$action_state" \
    SELHIDE_PROC_MODULES="$action_modules" \
    SELHIDE_ACTION_KEY_FILE="$action_state/action.key" \
    PATH="$action_bin:$PATH" \
        sh "$action_root/action.sh" > "$action_state/action.out" 2>&1
}

run_action up || fail "first Action trial failed"
[ -f "$action_state/trial_passed" ] || fail "first Action tap did not record trial"
[ ! -s "$action_modules" ] || fail "first Action tap left module loaded"
[ ! -e "$action_state/autoload" ] || fail "first Action tap enabled autoload"
run_action up || fail "second Action enable failed"
[ -f "$action_state/autoload" ] || fail "second Action tap did not enable autoload"
run_action up || fail "Action keep-state choice failed"
[ -f "$action_state/autoload" ] || fail "Volume Up did not preserve autoload"
run_action down || fail "third Action disable failed"
[ ! -e "$action_state/autoload" ] || fail "third Action tap did not disable autoload"
run_action none || fail "Action no-input fallback failed"
[ ! -e "$action_state/autoload" ] || fail "no-input fallback changed autoload"
find "$action_state" -maxdepth 1 -name '.action_getevent.*' | grep -q . &&
    fail "Action left a getevent capture file behind"

touch "$action_state/safe_mode"
printf '%s\n' "sha256=$action_module_sha" > \
    "$action_state/recovered_guard_20000101_000000.txt"
if run_action up; then
    fail "Action bypassed persistent safe mode"
fi
grep -Fq 'BLOCKED: persistent safe mode is active.' "$action_state/action.out" ||
    fail "Action did not explain safe-mode refusal"
grep -Fq 'same one associated with the uncleared panic guard' "$action_state/action.out" ||
    fail "Action did not reject the recovered artifact explicitly"

if [ -n "$ZIP_PATH" ]; then
    command -v unzip >/dev/null || fail "missing dependency: unzip"
    unzip -tq "$ZIP_PATH" >/dev/null
fi

echo "PASS: Magisk module shell safety checks"
echo "test_root=$test_root"
echo "state=$state"
echo "identity_root=$identity_root"
echo "identity_state=$identity_state"
echo "boot_root=$boot_root"
echo "boot_state=$boot_state"
echo "action_root=$action_root"
echo "action_state=$action_state"
