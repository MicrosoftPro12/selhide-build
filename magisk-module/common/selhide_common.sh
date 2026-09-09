#!/system/bin/sh

STATE_DIR="${SELHIDE_STATE_DIR:-/data/adb/selhide}"
PROC_MODULES="${SELHIDE_PROC_MODULES:-/proc/modules}"
LOG_FILE="$STATE_DIR/selhide.log"
STATUS_FILE="$STATE_DIR/status.env"
GUARD_FILE="$STATE_DIR/load_pending"
SAFE_MODE_FILE="$STATE_DIR/safe_mode"
AUTOLOAD_FILE="$STATE_DIR/autoload"
TRIAL_PASSED_FILE="$STATE_DIR/trial_passed"
APPLY_LIST_FILE="$STATE_DIR/apply-list.txt"
APPLY_APPIDS_FILE="$STATE_DIR/apply-appids.txt"
APPLY_MODE_FILE="$STATE_DIR/apply-mode"
APPLY_SYNC_PID_FILE="$STATE_DIR/apply-sync.pid"
HIDING_PAUSED_FILE="$STATE_DIR/hiding_paused"
MANIFEST="$MODDIR/payload/manifest.tsv"
LOADER="$MODDIR/bin/kallsyms_init_module"
POLICY_FILE="$STATE_DIR/clean_sepolicy_load"
CLEAN_ACCESS_PARAM="${SELHIDE_CLEAN_ACCESS_PARAM:-/sys/module/selhide/parameters/clean_access}"
APPLY_FILTER_PARAM="${SELHIDE_APPLY_FILTER_PARAM:-/sys/module/selhide/parameters/apply_filter}"
APPLY_APPIDS_PARAM="${SELHIDE_APPLY_APPIDS_PARAM:-/sys/module/selhide/parameters/apply_appids}"

ensure_state_dir() {
    mkdir -p "$STATE_DIR" 2>/dev/null || return 1
    chmod 0700 "$STATE_DIR" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null || true
    chmod 0600 "$LOG_FILE" 2>/dev/null || true
}

now() {
    date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || date 2>/dev/null || echo unknown
}

log_msg() {
    ensure_state_dir || true
    printf '%s %s\n' "$(now)" "$*" >> "$LOG_FILE"
}

write_status() {
    ensure_state_dir || return 1
    status_tmp="$(mktemp "$STATUS_FILE.tmp.XXXXXX")" || return 1
    {
        echo "updated=$(now)"
        echo "state=$1"
        echo "detail=${2:-}"
        echo "kernel=$(uname -r 2>/dev/null || true)"
        echo "module_loaded=$(module_is_loaded && echo 1 || echo 0)"
        echo "hiding_runtime=$(runtime_hiding_state)"
        echo "hiding_desired=$(desired_hiding_state)"
        echo "autoload=$([ -f "$AUTOLOAD_FILE" ] && echo 1 || echo 0)"
        echo "safe_mode=$([ -f "$SAFE_MODE_FILE" ] && echo 1 || echo 0)"
    } > "$status_tmp" && mv -f "$status_tmp" "$STATUS_FILE"
    status_rc=$?
    [ "$status_rc" -eq 0 ] || rm -f "$status_tmp"
    chmod 0600 "$STATUS_FILE" 2>/dev/null || true
    return "$status_rc"
}

load_defaults() {
    GUARD_SECONDS=120
    TRIAL_SECONDS=60
    # Consumed by service.sh after this library is sourced.
    # shellcheck disable=SC2034
    BOOT_DELAY_SECONDS=30
    # shellcheck disable=SC2034
    BOOT_WAIT_SECONDS=180
    TRACE_QUERIES=0
    TRACE_LIMIT=16
    ACTION_KEY_TIMEOUT_SECONDS=20
    APPLY_SYNC_SECONDS=30
    [ -r "$MODDIR/config/default.conf" ] && . "$MODDIR/config/default.conf"
    [ -r "$STATE_DIR/config.conf" ] && . "$STATE_DIR/config.conf"
}

wait_volume_key() {
    seconds="${1:-20}"
    VOLUME_KEY_RESULT=""
    case "$seconds" in
        ''|*[!0-9]*) seconds=20 ;;
    esac
    [ "$seconds" -gt 0 ] || return 1
    command -v getevent >/dev/null 2>&1 || return 2

    VOLUME_GETEVENT_FILE="$STATE_DIR/.action_getevent.$$"
    : > "$VOLUME_GETEVENT_FILE" || return 2
    getevent -ql > "$VOLUME_GETEVENT_FILE" 2>/dev/null &
    VOLUME_GETEVENT_PID=$!

    # Start getevent once. Some Android builds take several seconds to kill a
    # blocked getevent process, making repeated timeout(1) calls much too slow.
    remaining=$((seconds * 5))
    while [ "$remaining" -gt 0 ]; do
        event="$(grep -m 1 \
            -e 'KEY_VOLUMEUP' \
            -e 'KEY_VOLUMEDOWN' \
            "$VOLUME_GETEVENT_FILE" 2>/dev/null || true)"
        case "$event" in
            *KEY_VOLUMEUP*)
                cleanup_volume_key_listener
                VOLUME_KEY_RESULT=up
                return 0
                ;;
            *KEY_VOLUMEDOWN*)
                cleanup_volume_key_listener
                VOLUME_KEY_RESULT=down
                return 0
                ;;
        esac
        if ! kill -0 "$VOLUME_GETEVENT_PID" 2>/dev/null; then
            cleanup_volume_key_listener
            return 2
        fi
        sleep 0.2
        remaining=$((remaining - 1))
    done
    cleanup_volume_key_listener
    return 1
}

cleanup_volume_key_listener() {
    if [ -n "${VOLUME_GETEVENT_PID:-}" ]; then
        kill -9 "$VOLUME_GETEVENT_PID" 2>/dev/null || true
        wait "$VOLUME_GETEVENT_PID" 2>/dev/null || true
        VOLUME_GETEVENT_PID=""
    fi
    if [ -n "${VOLUME_GETEVENT_FILE:-}" ]; then
        rm -f "$VOLUME_GETEVENT_FILE"
        VOLUME_GETEVENT_FILE=""
    fi
}

module_is_loaded() {
    grep -q '^selhide ' "$PROC_MODULES" 2>/dev/null
}

desired_hiding_state() {
    if [ -f "$HIDING_PAUSED_FILE" ]; then
        echo passthrough
    else
        echo active
    fi
}

runtime_hiding_state() {
    module_is_loaded || {
        echo unloaded
        return 0
    }
    [ -r "$CLEAN_ACCESS_PARAM" ] || {
        echo unknown
        return 0
    }
    runtime_hiding_value="$(cat "$CLEAN_ACCESS_PARAM" 2>/dev/null || true)"
    case "$runtime_hiding_value" in
        1|Y|y|yes|true) echo active ;;
        0|N|n|no|false) echo passthrough ;;
        *) echo unknown ;;
    esac
}

set_runtime_hiding() {
    runtime_hiding_requested="$1"
    case "$runtime_hiding_requested" in
        1) runtime_hiding_expected=active ;;
        0) runtime_hiding_expected=passthrough ;;
        *) return 80 ;;
    esac

    ensure_state_dir || return 10
    if module_is_loaded; then
        [ -w "$CLEAN_ACCESS_PARAM" ] || {
            log_msg "runtime hiding change failed: parameter unavailable"
            write_status error clean-access-parameter-unavailable
            return 81
        }
        printf '%s\n' "$runtime_hiding_requested" > "$CLEAN_ACCESS_PARAM" || {
            log_msg "runtime hiding change failed: write error"
            write_status error clean-access-parameter-write-failed
            return 82
        }
        runtime_hiding_actual="$(runtime_hiding_state)"
        [ "$runtime_hiding_actual" = "$runtime_hiding_expected" ] || {
            log_msg "runtime hiding change failed: expected=$runtime_hiding_expected actual=$runtime_hiding_actual"
            write_status error clean-access-parameter-verify-failed
            return 83
        }
    fi

    if [ "$runtime_hiding_requested" -eq 1 ]; then
        rm -f "$HIDING_PAUSED_FILE"
        runtime_hiding_detail=active
    else
        touch "$HIDING_PAUSED_FILE" || return 84
        chmod 0600 "$HIDING_PAUSED_FILE" 2>/dev/null || true
        runtime_hiding_detail=passthrough
    fi
    sync
    write_status "hiding-$runtime_hiding_detail" runtime
    log_msg "runtime hiding state=$runtime_hiding_detail loaded=$(module_is_loaded && echo 1 || echo 0)"
    echo "hiding_runtime=$(runtime_hiding_state)"
    echo "hiding_desired=$(desired_hiding_state)"
}

toggle_runtime_hiding() {
    runtime_hiding_current="$(runtime_hiding_state)"
    case "$runtime_hiding_current" in
        active) set_runtime_hiding 0 ;;
        passthrough) set_runtime_hiding 1 ;;
        unloaded|unknown)
            if [ -f "$HIDING_PAUSED_FILE" ]; then
                set_runtime_hiding 1
            else
                set_runtime_hiding 0
            fi
            ;;
    esac
}

apply_list_mode() {
    apply_mode="$(cat "$APPLY_MODE_FILE" 2>/dev/null || true)"
    case "$apply_mode" in
        manual) echo manual ;;
        *) echo sync ;;
    esac
}

magisk_cli() {
    if command -v magisk >/dev/null 2>&1; then
        magisk "$@"
    elif [ -x /data/adb/magisk/magisk ]; then
        /data/adb/magisk/magisk "$@"
    else
        return 70
    fi
}

capture_magisk_denylist() {
    apply_output="$1"
    apply_raw="$(mktemp "$STATE_DIR/.magisk-denylist.XXXXXX")" || return 1
    magisk_cli --denylist ls < /dev/null > "$apply_raw" 2>/dev/null
    apply_rc=$?
    if [ "$apply_rc" -ne 0 ]; then
        rm -f "$apply_raw"
        return "$apply_rc"
    fi
    awk -F '|' '
        $1 ~ /^[A-Za-z0-9_]+([.][A-Za-z0-9_]+)*$/ { print $1 }
    ' "$apply_raw" | sort -u > "$apply_output"
    rm -f "$apply_raw"
}

normalize_apply_package() {
    apply_package="${1#package:}"
    case "$apply_package" in
        ''|.*|*.|*..*|*[!A-Za-z0-9._]*) return 90 ;;
    esac
    NORMALIZED_APPLY_PACKAGE="$apply_package"
}

query_package_uid_map() {
    query_output="$1"
    query_status="$(mktemp "$STATE_DIR/.package-uids-status.XXXXXX")" || return 1
    query_rc=71

    if command -v cmd >/dev/null 2>&1; then
        # PackageManager runs inside system_server and receives cmd's output
        # descriptor over Binder. It may reject a descriptor opened directly
        # on magisk_file, so bridge output through a pipe before writing state.
        { cmd package list packages -U < /dev/null 2>&1; echo "$?" > "$query_status"; } |
            cat > "$query_output"
        query_rc="$(cat "$query_status" 2>/dev/null || true)"
        case "$query_rc" in
            ''|*[!0-9]*) query_rc=1 ;;
        esac
        if [ "$query_rc" -eq 0 ]; then
            rm -f "$query_status"
            return 0
        fi
        query_detail="$(tail -n 1 "$query_output" 2>/dev/null | tr '\r\n' ' ' | cut -c 1-160)"
        log_msg "package UID query via cmd failed rc=$query_rc detail=$query_detail"
    fi

    if command -v pm >/dev/null 2>&1; then
        : > "$query_status"
        { pm list packages -U < /dev/null 2>&1; echo "$?" > "$query_status"; } |
            cat > "$query_output"
        query_rc="$(cat "$query_status" 2>/dev/null || true)"
        case "$query_rc" in
            ''|*[!0-9]*) query_rc=1 ;;
        esac
        if [ "$query_rc" -eq 0 ]; then
            log_msg "package UID query recovered via pm fallback"
            rm -f "$query_status"
            return 0
        fi
        query_detail="$(tail -n 1 "$query_output" 2>/dev/null | tr '\r\n' ' ' | cut -c 1-160)"
        log_msg "package UID query via pm failed rc=$query_rc detail=$query_detail"
    fi

    rm -f "$query_status"
    return "$query_rc"
}

build_apply_appids() {
    apply_source="$1"
    apply_output="$2"
    apply_packages="$(mktemp "$STATE_DIR/.apply-packages.XXXXXX")" || return 1
    apply_map="$(mktemp "$STATE_DIR/.package-uids.XXXXXX")" || {
        rm -f "$apply_packages"
        return 1
    }
    apply_raw_map="$(mktemp "$STATE_DIR/.package-uids-raw.XXXXXX")" || {
        rm -f "$apply_packages" "$apply_map"
        return 1
    }
    : > "$apply_packages"

    while IFS= read -r apply_entry || [ -n "$apply_entry" ]; do
        [ -n "$apply_entry" ] || continue
        normalize_apply_package "$apply_entry" || {
            rm -f "$apply_packages" "$apply_map" "$apply_raw_map"
            return 90
        }
        echo "$NORMALIZED_APPLY_PACKAGE" >> "$apply_packages"
    done < "$apply_source"
    sort -u "$apply_packages" > "$apply_packages.sorted"
    mv -f "$apply_packages.sorted" "$apply_packages"

    if ! command -v cmd >/dev/null 2>&1 && ! command -v pm >/dev/null 2>&1; then
        rm -f "$apply_packages" "$apply_map" "$apply_raw_map"
        return 71
    fi
    query_package_uid_map "$apply_raw_map"
    apply_rc=$?
    if [ "$apply_rc" -ne 0 ]; then
        rm -f "$apply_packages" "$apply_map" "$apply_raw_map"
        return "$apply_rc"
    fi
    awk '
        /^package:/ {
            package = substr($1, 9)
            for (i = 2; i <= NF; i++) {
                if ($i ~ /^uid:[0-9]+$/) {
                    uid = $i
                    sub(/^uid:/, "", uid)
                    print package "|" (uid % 100000)
                    break
                }
            }
        }
    ' "$apply_raw_map" > "$apply_map"

    awk -F '|' 'NR == FNR { wanted[$1] = 1; next } wanted[$1] { print $2 }' \
        "$apply_packages" "$apply_map" | sort -n -u > "$apply_output"
    rm -f "$apply_packages" "$apply_map" "$apply_raw_map"
    apply_appid_count="$(awk 'END { print NR + 0 }' "$apply_output")"
    [ "$apply_appid_count" -le 256 ] || return 91
}

apply_appids_csv() {
    apply_csv=""
    [ -r "$APPLY_APPIDS_FILE" ] || {
        echo ""
        return 0
    }
    while IFS= read -r apply_appid || [ -n "$apply_appid" ]; do
        [ -n "$apply_appid" ] || continue
        apply_csv="${apply_csv}${apply_csv:+,}${apply_appid}"
    done < "$APPLY_APPIDS_FILE"
    echo "$apply_csv"
}

apply_appids_param_value() {
    apply_value="$(apply_appids_csv)"
    # module_param_array requires at least one element. UINT_MAX can never
    # equal an Android appId and therefore represents an empty selected set.
    [ -n "$apply_value" ] && echo "$apply_value" || echo 4294967295
}

apply_packages_csv() {
    apply_csv=""
    [ -r "$APPLY_LIST_FILE" ] || {
        echo ""
        return 0
    }
    while IFS= read -r apply_package || [ -n "$apply_package" ]; do
        [ -n "$apply_package" ] || continue
        apply_csv="${apply_csv}${apply_csv:+,}${apply_package}"
    done < "$APPLY_LIST_FILE"
    echo "$apply_csv"
}

apply_runtime_appids() {
    apply_value="$(apply_appids_param_value)"
    module_is_loaded || return 0
    [ -w "$APPLY_APPIDS_PARAM" ] && [ -w "$APPLY_FILTER_PARAM" ] || return 92
    apply_previous="$(tr -d '\r\n ' < "$APPLY_APPIDS_PARAM" 2>/dev/null)"
    apply_previous_filter="$(tr -d '\r\n ' < "$APPLY_FILTER_PARAM" 2>/dev/null)"
    [ -n "$apply_previous" ] || apply_previous=4294967295
    case "$apply_previous_filter" in
        1|Y|y|yes|true) apply_previous_filter=1 ;;
        *) apply_previous_filter=0 ;;
    esac

    printf '%s\n' "$apply_value" > "$APPLY_APPIDS_PARAM" || return 93
    if ! printf '%s\n' 1 > "$APPLY_FILTER_PARAM"; then
        printf '%s\n' "$apply_previous" > "$APPLY_APPIDS_PARAM" 2>/dev/null || true
        return 93
    fi
    apply_actual="$(tr -d '\r\n ' < "$APPLY_APPIDS_PARAM" 2>/dev/null)"
    apply_filter_actual="$(tr -d '\r\n ' < "$APPLY_FILTER_PARAM" 2>/dev/null)"
    if [ "$apply_actual" != "$apply_value" ]; then
        printf '%s\n' "$apply_previous" > "$APPLY_APPIDS_PARAM" 2>/dev/null || true
        printf '%s\n' "$apply_previous_filter" > "$APPLY_FILTER_PARAM" 2>/dev/null || true
        return 94
    fi
    case "$apply_filter_actual" in
        1|Y|y|yes|true) ;;
        *)
            printf '%s\n' "$apply_previous" > "$APPLY_APPIDS_PARAM" 2>/dev/null || true
            printf '%s\n' "$apply_previous_filter" > "$APPLY_FILTER_PARAM" 2>/dev/null || true
            return 94
            ;;
    esac
}

save_apply_candidate() {
    apply_candidate="$1"
    apply_appids_tmp="$(mktemp "$APPLY_APPIDS_FILE.tmp.XXXXXX")" || return 1
    build_apply_appids "$apply_candidate" "$apply_appids_tmp"
    apply_rc=$?
    if [ "$apply_rc" -ne 0 ]; then
        rm -f "$apply_candidate" "$apply_appids_tmp"
        return "$apply_rc"
    fi

    apply_old_appids_file="$APPLY_APPIDS_FILE"
    APPLY_APPIDS_FILE="$apply_appids_tmp"
    apply_runtime_appids
    apply_rc=$?
    APPLY_APPIDS_FILE="$apply_old_appids_file"
    if [ "$apply_rc" -ne 0 ]; then
        rm -f "$apply_candidate" "$apply_appids_tmp"
        return "$apply_rc"
    fi

    mv -f "$apply_candidate" "$APPLY_LIST_FILE"
    mv -f "$apply_appids_tmp" "$APPLY_APPIDS_FILE"
    chmod 0600 "$APPLY_LIST_FILE" "$APPLY_APPIDS_FILE" 2>/dev/null || true
    write_status apply-list-updated "$(apply_list_mode)"
    log_msg "apply list updated mode=$(apply_list_mode) packages=$(awk 'END { print NR + 0 }' "$APPLY_LIST_FILE") appids=$(awk 'END { print NR + 0 }' "$APPLY_APPIDS_FILE")"
}

refresh_apply_list_from_magisk() {
    ensure_state_dir || return 10
    apply_candidate="$(mktemp "$APPLY_LIST_FILE.tmp.XXXXXX")" || return 1
    capture_magisk_denylist "$apply_candidate" || {
        apply_rc=$?
        rm -f "$apply_candidate"
        return "$apply_rc"
    }
    save_apply_candidate "$apply_candidate"
}

prepare_apply_list() {
    ensure_state_dir || return 10
    if [ "$(apply_list_mode)" = sync ]; then
        refresh_apply_list_from_magisk
        return $?
    fi

    [ -r "$APPLY_LIST_FILE" ] || : > "$APPLY_LIST_FILE"
    apply_appids_tmp="$(mktemp "$APPLY_APPIDS_FILE.tmp.XXXXXX")" || return 1
    build_apply_appids "$APPLY_LIST_FILE" "$apply_appids_tmp"
    apply_rc=$?
    if [ "$apply_rc" -ne 0 ]; then
        rm -f "$apply_appids_tmp"
        return "$apply_rc"
    fi
    mv -f "$apply_appids_tmp" "$APPLY_APPIDS_FILE"
    chmod 0600 "$APPLY_LIST_FILE" "$APPLY_APPIDS_FILE" 2>/dev/null || true
}

apply_sync_watcher_running() {
    APPLY_SYNC_PID="$(awk -F= '$1 == "pid" { print $2; exit }' "$APPLY_SYNC_PID_FILE" 2>/dev/null)"
    apply_saved_boot="$(awk -F= '$1 == "boot_id" { print $2; exit }' "$APPLY_SYNC_PID_FILE" 2>/dev/null)"
    apply_saved_start="$(awk -F= '$1 == "starttime" { print $2; exit }' "$APPLY_SYNC_PID_FILE" 2>/dev/null)"
    apply_current_boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
    apply_current_start="$(awk '{ print $22 }' "/proc/$APPLY_SYNC_PID/stat" 2>/dev/null)"
    case "$APPLY_SYNC_PID" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ -n "$apply_saved_start" ] &&
        [ "$apply_saved_boot" = "$apply_current_boot" ] &&
        [ "$apply_saved_start" = "$apply_current_start" ] &&
        kill -0 "$APPLY_SYNC_PID" 2>/dev/null
}

stop_apply_sync_watcher() {
    if apply_sync_watcher_running; then
        kill "$APPLY_SYNC_PID" 2>/dev/null || true
    fi
    rm -f "$APPLY_SYNC_PID_FILE"
}

start_apply_sync_watcher() {
    [ "$(apply_list_mode)" = sync ] || return 0
    module_is_loaded || return 0
    apply_sync_watcher_running && return 0
    case "$APPLY_SYNC_SECONDS" in
        ''|*[!0-9]*) APPLY_SYNC_SECONDS=30 ;;
    esac
    [ "$APPLY_SYNC_SECONDS" -ge 5 ] || APPLY_SYNC_SECONDS=5

    (
        while module_is_loaded && [ "$(apply_list_mode)" = sync ]; do
            sleep "$APPLY_SYNC_SECONDS"
            module_is_loaded || break
            [ "$(apply_list_mode)" = sync ] || break
            refresh_apply_list_from_magisk >/dev/null 2>&1 ||
                log_msg "continuous Magisk denylist sync failed rc=$?"
        done
    ) >/dev/null 2>&1 &
    apply_pid="$!"
    apply_start="$(awk '{ print $22 }' "/proc/$apply_pid/stat" 2>/dev/null)"
    [ -n "$apply_start" ] || {
        kill "$apply_pid" 2>/dev/null || true
        return 1
    }
    {
        echo "pid=$apply_pid"
        echo "boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
        echo "starttime=$apply_start"
    } > "$APPLY_SYNC_PID_FILE"
    chmod 0600 "$APPLY_SYNC_PID_FILE" 2>/dev/null || true
}

set_apply_list_mode() {
    apply_requested_mode="$1"
    case "$apply_requested_mode" in
        sync|manual) ;;
        *) return 95 ;;
    esac

    # Both transitions begin from a fresh Magisk denylist snapshot. Manual
    # mode then unlocks editing; sync mode keeps replacing that snapshot.
    refresh_apply_list_from_magisk || return $?
    echo "$apply_requested_mode" > "$APPLY_MODE_FILE" || return 1
    chmod 0600 "$APPLY_MODE_FILE" 2>/dev/null || true
    if [ "$apply_requested_mode" = sync ]; then
        start_apply_sync_watcher
    else
        stop_apply_sync_watcher
    fi
    write_status apply-mode "$apply_requested_mode"
}

add_apply_package() {
    [ "$(apply_list_mode)" = manual ] || return 96
    normalize_apply_package "$1" || return $?
    ensure_state_dir || return 10
    apply_candidate="$(mktemp "$APPLY_LIST_FILE.tmp.XXXXXX")" || return 1
    { [ ! -r "$APPLY_LIST_FILE" ] || cat "$APPLY_LIST_FILE"; echo "$NORMALIZED_APPLY_PACKAGE"; } |
        sort -u > "$apply_candidate"
    save_apply_candidate "$apply_candidate"
}

remove_apply_package() {
    [ "$(apply_list_mode)" = manual ] || return 96
    normalize_apply_package "$1" || return $?
    ensure_state_dir || return 10
    apply_candidate="$(mktemp "$APPLY_LIST_FILE.tmp.XXXXXX")" || return 1
    awk -v removed="$NORMALIZED_APPLY_PACKAGE" '$0 != removed' "$APPLY_LIST_FILE" \
        2>/dev/null > "$apply_candidate"
    save_apply_candidate "$apply_candidate"
}

clear_apply_list() {
    [ "$(apply_list_mode)" = manual ] || return 96
    ensure_state_dir || return 10
    apply_candidate="$(mktemp "$APPLY_LIST_FILE.tmp.XXXXXX")" || return 1
    : > "$apply_candidate"
    save_apply_candidate "$apply_candidate"
}

sha256_file() {
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

select_module() {
    SELECTED_RELEASE="$(uname -r 2>/dev/null || true)"
    [ -n "$SELECTED_RELEASE" ] || return 20
    [ -r "$MANIFEST" ] || return 21

    SELECTED_LINE="$(awk -F '|' -v release="$SELECTED_RELEASE" '
        $0 !~ /^#/ && $1 == release { print; exit }
    ' "$MANIFEST")"
    [ -n "$SELECTED_LINE" ] || return 22

    SELECTED_RELATIVE="$(printf '%s\n' "$SELECTED_LINE" | cut -d '|' -f 2)"
    SELECTED_SHA256="$(printf '%s\n' "$SELECTED_LINE" | cut -d '|' -f 3)"
    SELECTED_LABEL="$(printf '%s\n' "$SELECTED_LINE" | cut -d '|' -f 4-)"
    SELECTED_KO="$MODDIR/$SELECTED_RELATIVE"
    [ -f "$SELECTED_KO" ] || return 23

    if [ -n "$SELECTED_SHA256" ] && [ "$SELECTED_SHA256" != "-" ]; then
        actual_sha256="$(sha256_file "$SELECTED_KO")"
        [ "$actual_sha256" = "$SELECTED_SHA256" ] || return 24
    fi
    return 0
}

ensure_clean_policy() {
    finder="$MODDIR/bin/find_clean_sepolicy_load.sh"
    [ -x "$finder" ] || return 30
    OUT_DIR="$STATE_DIR" OUT="$POLICY_FILE" \
        REPORT="$STATE_DIR/clean_sepolicy_report.txt" "$finder"
}

detect_setprocattr_cfi_symbol() {
    grep -E -m1 -o 'selinux_setprocattr[^ ]*\.cfi_jt' \
        /proc/kallsyms 2>/dev/null || true
}

run_preflight() {
    ensure_state_dir || return 10
    select_module || {
        rc=$?
        log_msg "preflight module selection failed rc=$rc kernel=$(uname -r 2>/dev/null)"
        write_status incompatible "module-selection-rc-$rc"
        return "$rc"
    }
    [ -x "$LOADER" ] || {
        log_msg "preflight loader missing"
        write_status error loader-missing
        return 25
    }
    ensure_clean_policy || {
        rc=$?
        log_msg "preflight clean policy failed rc=$rc"
        write_status incompatible clean-policy-missing
        return "$rc"
    }

    log_msg "preflight start label=$SELECTED_LABEL ko=$SELECTED_RELATIVE"
    "$LOADER" --check-vermagic "$SELECTED_KO" >> "$LOG_FILE" 2>&1 || {
        rc=$?
        log_msg "preflight vermagic check failed rc=$rc"
        write_status incompatible "vermagic-rc-$rc"
        return "$rc"
    }
    "$LOADER" --dry-run "$SELECTED_KO" >> "$LOG_FILE" 2>&1 || {
        rc=$?
        log_msg "preflight symbol check failed rc=$rc"
        write_status incompatible "symbol-check-rc-$rc"
        return "$rc"
    }
    write_status ready "$SELECTED_LABEL"
    log_msg "preflight passed"
    return 0
}

arm_panic_guard() {
    mode="$1"
    boot_id="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
    guard_nonce="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
    [ -n "$guard_nonce" ] || guard_nonce="$$:$(date +%s 2>/dev/null || echo unknown)"
    ARMED_GUARD_ID="$boot_id:$guard_nonce"
    {
        echo "guard_id=$ARMED_GUARD_ID"
        echo "armed=$(now)"
        echo "boot_id=$boot_id"
        echo "mode=$mode"
        echo "kernel=$(uname -r 2>/dev/null || true)"
        echo "module=$SELECTED_RELATIVE"
        echo "sha256=$SELECTED_SHA256"
    } > "$GUARD_FILE.tmp" && mv -f "$GUARD_FILE.tmp" "$GUARD_FILE"
    chmod 0600 "$GUARD_FILE" 2>/dev/null || true
    sync
    log_msg "panic guard armed mode=$mode"
}

clear_panic_guard() {
    expected_id="${1:-}"
    if [ -n "$expected_id" ]; then
        grep -Fqx "guard_id=$expected_id" "$GUARD_FILE" 2>/dev/null || return 1
    fi
    rm -f "$GUARD_FILE"
    sync
    log_msg "panic guard cleared"
}

start_guard_watcher() {
    seconds="$1"
    expected_guard_id="$2"
    selected_label="$3"
    expected_boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
    (
        sleep "$seconds"
        current_boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
        if [ "$current_boot" = "$expected_boot" ] && module_is_loaded; then
            if clear_panic_guard "$expected_guard_id"; then
                write_status loaded-stable "$selected_label"
            fi
        fi
    ) >/dev/null 2>&1 &
}

load_guarded() {
    mode="${1:-manual}"
    [ ! -f "$SAFE_MODE_FILE" ] || {
        write_status blocked safe-mode
        log_msg "load refused: safe mode active"
        return 40
    }
    module_is_loaded && return 0
    run_preflight || return $?
    if [ "$mode" = "autoload" ] && ! trial_matches_current; then
        log_msg "autoload refused: trial identity does not match current runtime"
        write_status blocked trial-identity-mismatch
        return 60
    fi
    prepare_apply_list
    apply_rc=$?
    if [ "$apply_rc" -ne 0 ]; then
        log_msg "load refused: apply list unavailable rc=$apply_rc mode=$(apply_list_mode)"
        write_status blocked "apply-list-rc-$apply_rc"
        echo "ERROR: application scope preparation failed (rc=$apply_rc, mode=$(apply_list_mode))." >&2
        echo "Retry after Android Package Manager is ready, then refresh the apply list." >&2
        return 61
    fi
    arm_panic_guard "$mode" || return 41
    guard_id="$ARMED_GUARD_ID"

    clean_access_value=1
    if [ "$mode" != "trial" ] && [ -f "$HIDING_PAUSED_FILE" ]; then
        clean_access_value=0
    fi

    set -- \
        access_hook=1 \
        "clean_access=$clean_access_value" \
        context_hook=1 \
        setprocattr_hook=1 \
        "trace_queries=$TRACE_QUERIES" \
        "trace_limit=$TRACE_LIMIT" \
        "policy_path=$POLICY_FILE"
    cfi_symbol="$(detect_setprocattr_cfi_symbol)"
    [ -z "$cfi_symbol" ] || set -- "$@" "setprocattr_cfi_symbol=$cfi_symbol"
    apply_value="$(apply_appids_param_value)"
    set -- "$@" "apply_appids=$apply_value"
    set -- "$@" apply_filter=1

    log_msg "load start mode=$mode"
    "$LOADER" "$SELECTED_KO" "$@" >> "$LOG_FILE" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ] || ! module_is_loaded; then
        log_msg "load failed rc=$rc loaded=$(module_is_loaded && echo 1 || echo 0)"
        clear_panic_guard
        write_status error "load-rc-$rc"
        return "$rc"
    fi

    write_status loaded-guarded "$mode"
    log_msg "load passed; guard window=${GUARD_SECONDS}s"
    start_guard_watcher "$GUARD_SECONDS" "$guard_id" "$SELECTED_LABEL"
    start_apply_sync_watcher
    return 0
}

unload_module() {
    stop_apply_sync_watcher
    if module_is_loaded; then
        rmmod selhide >> "$LOG_FILE" 2>&1 || return $?
    fi
    clear_panic_guard
    write_status unloaded manual
    log_msg "module unloaded"
}

run_trial() {
    seconds="${1:-$TRIAL_SECONDS}"
    case "$seconds" in
        ''|*[!0-9]*) return 50 ;;
    esac
    [ "$seconds" -ge 5 ] || seconds=5
    load_guarded trial || return $?
    log_msg "trial holding for ${seconds}s"
    sleep "$seconds"
    module_is_loaded || return 51
    unload_module || return $?
    record_trial_passed || return $?
    write_status trial-passed "${seconds}s"
    log_msg "trial passed"
}

enable_autoload() {
    run_preflight || return $?
    trial_matches_current || {
        log_msg "autoload refused: no trial for current runtime identity"
        write_status blocked trial-required-for-current-artifact
        echo "ERROR: the current KO, loader, and clean policy have not passed a guarded trial." >&2
        echo "Run 'selhide_ctl.sh trial $TRIAL_SECONDS', then enable autoload again." >&2
        return 60
    }
    rm -f "$SAFE_MODE_FILE" "$MODDIR/disable"
    touch "$AUTOLOAD_FILE"
    chmod 0600 "$AUTOLOAD_FILE" 2>/dev/null || true
    write_status autoload-enabled reboot-required
    log_msg "autoload enabled"
}

runtime_identity() {
    select_module || return $?
    [ -x "$LOADER" ] || return 25
    [ -r "$POLICY_FILE" ] || return 30
    IDENTITY_KERNEL="$SELECTED_RELEASE"
    IDENTITY_MODULE_SHA256="$(sha256_file "$SELECTED_KO")"
    IDENTITY_LOADER_SHA256="$(sha256_file "$LOADER")"
    IDENTITY_POLICY_SHA256="$(sha256_file "$POLICY_FILE")"
    [ -n "$IDENTITY_MODULE_SHA256" ] || return 71
    [ -n "$IDENTITY_LOADER_SHA256" ] || return 72
    [ -n "$IDENTITY_POLICY_SHA256" ] || return 73
}

record_trial_passed() {
    runtime_identity || return $?
    {
        echo "version=1"
        echo "passed=$(now)"
        echo "kernel=$IDENTITY_KERNEL"
        echo "module_sha256=$IDENTITY_MODULE_SHA256"
        echo "loader_sha256=$IDENTITY_LOADER_SHA256"
        echo "policy_sha256=$IDENTITY_POLICY_SHA256"
    } > "$TRIAL_PASSED_FILE.tmp" &&
        mv -f "$TRIAL_PASSED_FILE.tmp" "$TRIAL_PASSED_FILE"
    chmod 0600 "$TRIAL_PASSED_FILE" 2>/dev/null || true
    sync
}

trial_matches_current() {
    [ -r "$TRIAL_PASSED_FILE" ] || return 1
    runtime_identity || return $?
    grep -Fqx "version=1" "$TRIAL_PASSED_FILE" 2>/dev/null &&
        grep -Fqx "kernel=$IDENTITY_KERNEL" "$TRIAL_PASSED_FILE" 2>/dev/null &&
        grep -Fqx "module_sha256=$IDENTITY_MODULE_SHA256" "$TRIAL_PASSED_FILE" 2>/dev/null &&
        grep -Fqx "loader_sha256=$IDENTITY_LOADER_SHA256" "$TRIAL_PASSED_FILE" 2>/dev/null &&
        grep -Fqx "policy_sha256=$IDENTITY_POLICY_SHA256" "$TRIAL_PASSED_FILE" 2>/dev/null
}

disable_autoload() {
    rm -f "$AUTOLOAD_FILE"
    write_status autoload-disabled manual
    log_msg "autoload disabled"
}

import_magisk_denylist() {
    set_apply_list_mode manual
}

recover_from_pending_guard() {
    [ -f "$GUARD_FILE" ] || return 1
    ensure_state_dir || return 1
    stamp="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo unknown)"
    cp -f "$GUARD_FILE" "$STATE_DIR/recovered_guard_$stamp.txt" 2>/dev/null || true
    evidence_dir="$STATE_DIR/recovery_$stamp"
    mkdir -p "$evidence_dir" 2>/dev/null || true
    chmod 0700 "$evidence_dir" 2>/dev/null || true
    if [ -d /sys/fs/pstore ]; then
        for entry in /sys/fs/pstore/*; do
            [ -f "$entry" ] || continue
            cp -f "$entry" "$evidence_dir/" 2>/dev/null || true
        done
    fi
    {
        echo "recovered=$(now)"
        uname -a 2>/dev/null || true
        getprop ro.product.device 2>/dev/null || true
        getprop ro.build.fingerprint 2>/dev/null || true
    } > "$evidence_dir/device.txt" 2>/dev/null || true
    rm -f "$AUTOLOAD_FILE"
    touch "$SAFE_MODE_FILE" "$MODDIR/disable"
    rm -f "$GUARD_FILE"
    sync
    log_msg "uncleared panic guard detected; module self-disabled"
    write_status self-disabled uncleared-panic-guard
    return 0
}
