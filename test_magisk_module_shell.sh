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
action_param="$action_state/clean_access"
action_apply_param="$action_state/apply_appids"
action_filter_param="$action_state/apply_filter"
cp -a "$MODULE_ROOT/." "$action_root/"
mkdir -p "$action_root/payload/modules/test" "$action_root/bin"
printf '%s\n' module > "$action_root/payload/modules/test/selhide.ko"
action_module_sha="$(sha256sum "$action_root/payload/modules/test/selhide.ko" | awk '{print $1}')"
printf '%s\n' \
    '# exact_kernel_release|relative_module_path|sha256|label' \
    "$(uname -r)|payload/modules/test/selhide.ko|$action_module_sha|action-test" \
    > "$action_root/payload/manifest.tsv"
: > "$action_modules"
printf '%s\n' 1 > "$action_param"
: > "$action_apply_param"
printf '%s\n' 0 > "$action_filter_param"
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
for argument in "$@"; do
    case "$argument" in
        clean_access=*) printf '%s\n' "${argument#*=}" > "$SELHIDE_CLEAN_ACCESS_PARAM" ;;
        apply_appids=*) printf '%s\n' "${argument#*=}" > "$SELHIDE_APPLY_APPIDS_PARAM" ;;
        apply_filter=*) printf '%s\n' "${argument#*=}" > "$SELHIDE_APPLY_FILTER_PARAM" ;;
    esac
done
EOF
cat > "$action_bin/rmmod" <<'EOF'
#!/bin/sh
: > "$SELHIDE_PROC_MODULES"
EOF
cat > "$action_bin/sleep" <<'EOF'
#!/bin/sh
case "${1:-}" in
    300) exec /bin/sleep 300 ;;
esac
exit 0
EOF
cat > "$action_bin/magisk" <<'EOF'
#!/bin/sh
[ "${1:-}" = --denylist ] && [ "${2:-}" = ls ] || exit 2
printf '%s\n' \
    'com.example.alpha|com.example.alpha' \
    'com.example.beta|com.example.beta:worker'
EOF
cat > "$action_bin/cmd" <<'EOF'
#!/bin/sh
[ "$*" = 'package list packages -U' ] || exit 2
printf '%s\n' \
    'package:com.example.alpha uid:10123' \
    'package:com.example.beta uid:10124' \
    'package:com.example.extra uid:10125'
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
    "$action_bin/sleep" "$action_bin/getevent" "$action_bin/magisk" \
    "$action_bin/cmd"
printf '%s\n' 'GUARD_SECONDS=5' 'TRIAL_SECONDS=5' 'APPLY_SYNC_SECONDS=300' > "$action_state/config.conf"

run_action() {
    printf '%s\n' "$1" > "$action_state/action.key"
    SELHIDE_STATE_DIR="$action_state" \
    SELHIDE_PROC_MODULES="$action_modules" \
    SELHIDE_CLEAN_ACCESS_PARAM="$action_param" \
    SELHIDE_APPLY_APPIDS_PARAM="$action_apply_param" \
    SELHIDE_APPLY_FILTER_PARAM="$action_filter_param" \
    SELHIDE_ACTION_KEY_FILE="$action_state/action.key" \
    PATH="$action_bin:$PATH" \
        sh "$action_root/action.sh" > "$action_state/action.out" 2>&1
}

run_ctl() {
    SELHIDE_STATE_DIR="$action_state" \
    SELHIDE_PROC_MODULES="$action_modules" \
    SELHIDE_CLEAN_ACCESS_PARAM="$action_param" \
    SELHIDE_APPLY_APPIDS_PARAM="$action_apply_param" \
    SELHIDE_APPLY_FILTER_PARAM="$action_filter_param" \
    PATH="$action_bin:$PATH" \
        sh "$action_root/bin/selhide_ctl.sh" "$@"
}

if run_ctl enable-autoload > "$action_state/autoload-error.out" 2>&1; then
    fail "autoload was enabled before a guarded trial"
fi
grep -Fq 'have not passed a guarded trial' "$action_state/autoload-error.out" ||
    fail "autoload refusal did not explain error 60"
pretrial_web_status="$(run_ctl web-status)"
printf '%s\n' "$pretrial_web_status" | grep -Fx 'trial_seconds=5' >/dev/null ||
    fail "WebUI status missed configured trial duration"

run_action up || fail "first Action trial failed"
[ -f "$action_state/trial_passed" ] || fail "first Action tap did not record trial"
[ ! -s "$action_modules" ] || fail "first Action tap left module loaded"
[ ! -e "$action_state/autoload" ] || fail "first Action tap enabled autoload"
[ "$(cat "$action_apply_param")" = '10123,10124' ] ||
    fail "trial did not receive Magisk denylist appIds"
case "$(cat "$action_filter_param")" in
    1|Y|y) ;;
    *) fail "trial did not enable apply-list filtering" ;;
esac

# Sync mode mirrors Magisk and rejects edits. Manual mode starts from a fresh
# snapshot and applies add/remove operations to a loaded module immediately.
printf '%s\n' 'selhide 1 0 - Live 0x0' > "$action_modules"
run_ctl apply-sync-now >/dev/null || fail "explicit Magisk denylist sync failed"
if run_ctl apply-add com.example.extra >/dev/null 2>&1; then
    fail "sync mode allowed manual editing"
fi
run_ctl apply-mode-manual >/dev/null || fail "manual snapshot mode failed"
[ "$(cat "$action_state/apply-mode")" = manual ] || fail "manual mode was not persisted"
run_ctl apply-add com.example.extra >/dev/null || fail "manual package add failed"
[ "$(cat "$action_apply_param")" = '10123,10124,10125' ] ||
    fail "manual package add did not update runtime appIds"
run_ctl apply-remove com.example.beta >/dev/null || fail "manual package remove failed"
[ "$(cat "$action_apply_param")" = '10123,10125' ] ||
    fail "manual package remove did not update runtime appIds"
apply_status="$(run_ctl web-status)"
printf '%s\n' "$apply_status" | grep -Fx 'apply_mode=manual' >/dev/null ||
    fail "WebUI status missed manual apply-list mode"
printf '%s\n' "$apply_status" | grep -Fx 'apply_packages=com.example.alpha,com.example.extra' >/dev/null ||
    fail "WebUI status missed selected packages"
run_ctl apply-clear >/dev/null || fail "manual apply-list clear failed"
[ "$(tr -d '\r\n ' < "$action_apply_param")" = 4294967295 ] ||
    fail "manual clear did not install the empty-list sentinel"
run_ctl apply-mode-sync >/dev/null || fail "continuous sync mode failed"
[ "$(cat "$action_apply_param")" = '10123,10124' ] ||
    fail "sync mode did not restore Magisk denylist appIds"
run_ctl apply-mode-manual >/dev/null || fail "could not stop sync watcher for remaining tests"

printf '%s\n' 1 > "$action_param"
run_ctl hiding-off >/dev/null || fail "runtime hiding-off failed"
[ "$(cat "$action_param")" = 0 ] || fail "hiding-off did not update runtime parameter"
[ -f "$action_state/hiding_paused" ] || fail "hiding-off was not persisted"
run_ctl hiding-on >/dev/null || fail "runtime hiding-on failed"
[ "$(cat "$action_param")" = 1 ] || fail "hiding-on did not update runtime parameter"
[ ! -e "$action_state/hiding_paused" ] || fail "hiding-on pause marker survived"
web_status="$(run_ctl web-status)"
printf '%s\n' "$web_status" | grep -Fx 'hiding_runtime=active' >/dev/null ||
    fail "WebUI status missed active mode"
: > "$action_modules"

run_action up || fail "second Action enable failed"
[ -f "$action_state/autoload" ] || fail "second Action tap did not enable autoload"
run_action up || fail "Action pause choice failed"
[ -f "$action_state/hiding_paused" ] || fail "Volume Up did not pause hiding"
[ -f "$action_state/autoload" ] || fail "runtime pause changed autoload"
run_action up || fail "Action resume choice failed"
[ ! -e "$action_state/hiding_paused" ] || fail "Volume Up did not resume hiding"
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
    for entry in webroot/index.html webroot/app.js webroot/style.css; do
        unzip -Z1 "$ZIP_PATH" | grep -Fx "$entry" >/dev/null ||
            fail "ZIP is missing $entry"
    done
fi

grep -Fq '"trial",' "$MODULE_ROOT/webroot/app.js" ||
    fail "WebUI command allowlist is missing guarded trial"
grep -Fq 'navigator?.languages' "$MODULE_ROOT/webroot/app.js" ||
    fail "WebUI does not inspect the system language"
grep -Fq 'id="language-toggle"' "$MODULE_ROOT/webroot/index.html" ||
    fail "WebUI language control is missing"

echo "PASS: Magisk module shell safety checks"
echo "test_root=$test_root"
echo "state=$state"
echo "identity_root=$identity_root"
echo "identity_state=$identity_state"
echo "boot_root=$boot_root"
echo "boot_state=$boot_state"
echo "action_root=$action_root"
echo "action_state=$action_state"
