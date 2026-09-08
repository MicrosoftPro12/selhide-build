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
