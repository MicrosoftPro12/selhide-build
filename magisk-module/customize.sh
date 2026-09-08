#!/system/bin/sh

ui_print "- SelHide experimental guarded installer"
[ "$ARCH" = "arm64" ] || abort "! Only arm64 is supported"

STATE_DIR=/data/adb/selhide
mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"

if [ ! -f "$STATE_DIR/installed" ]; then
    rm -f "$STATE_DIR/autoload" "$STATE_DIR/trial_passed" \
        "$STATE_DIR/load_pending" "$STATE_DIR/safe_mode"
    echo "installed=$(date 2>/dev/null || true)" > "$STATE_DIR/installed"
    chmod 0600 "$STATE_DIR/installed"
    ui_print "- First install: autoload is OFF"
else
    ui_print "- Update install: persistent safety state preserved"
fi

release="$(uname -r 2>/dev/null || true)"
if awk -F '|' -v release="$release" '$0 !~ /^#/ && $1 == release { found=1 } END { exit !found }' \
    "$MODPATH/payload/manifest.tsv"; then
    ui_print "- Exact artifact found for $release"
else
    ui_print "! No exact artifact for $release"
    ui_print "! Module will remain installed but cannot load"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm "$MODPATH/bin/selhide_ctl.sh" 0 0 0755
set_perm "$MODPATH/bin/find_clean_sepolicy_load.sh" 0 0 0755
set_perm "$MODPATH/bin/kallsyms_init_module" 0 0 0755

ui_print "- Flashing never loads the LKM"
ui_print "- Action uses volume keys for guarded configuration"
ui_print "- No key or a timeout always leaves the current state unchanged"
