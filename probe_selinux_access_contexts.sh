#!/system/bin/sh
# Probe which MagiskSU -Z context can successfully transact with
# /sys/fs/selinux/access on this device. Writes output to the current dir.

case "$0" in
    */*) SCRIPT_DIR="${0%/*}" ;;
    *) SCRIPT_DIR="." ;;
esac
cd "$SCRIPT_DIR" 2>/dev/null || true

OUT="${OUT:-./probe_selinux_access_contexts_$(date +%Y%m%d_%H%M%S).txt}"

main() {
    echo "== meta =="
    date
    uname -a
    id
    echo "caller_ctx=$(cat /proc/self/attr/current 2>/dev/null)"
    ls -l /sys/fs/selinux/access 2>&1

    echo
    echo "== contexts =="
    for ctx in \
        u:r:init:s0 \
        u:r:magisk:s0 \
        u:r:su:s0 \
        u:r:shell:s0 \
        u:r:system_server:s0 \
        u:r:zygote:s0
    do
        echo "-- $ctx --"
        su -Z "$ctx" -c '
            echo "id=$(id 2>/dev/null)"
            echo "ctx=$(cat /proc/self/attr/current 2>/dev/null)"
            idx=$(cat /sys/fs/selinux/class/process/index 2>/dev/null || true)
            tmp=./.access_ctx_$$.out
            (
                exec 3<> /sys/fs/selinux/access || exit 11
                printf "%s %s %s" "u:r:shell:s0" "u:r:su:s0" "$idx" >&3 || exit 12
                dd bs=4096 count=1 <&3 2>/dev/null
                exit $?
            ) > "$tmp" 2>&1
            rc=$?
            raw=$(tr "\n" " " < "$tmp" 2>/dev/null)
            rm -f "$tmp"
            echo "rc=$rc raw=$raw"
        ' 2>&1
    done
}

main > "$OUT" 2>&1
rc=$?
echo "$OUT"
exit "$rc"
