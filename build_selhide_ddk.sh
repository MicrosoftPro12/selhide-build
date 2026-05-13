#!/usr/bin/env bash
set -euo pipefail

# Build selhide inside an Android DDK/GKI build container.
#
# Intended usage:
#   # Inside ghcr.io/ylarod/ddk-min:<kmi>-20260313
#   cd /workdir
#   ./build_selhide_ddk.sh
#
# Useful overrides:
#   KMI=android16-6.12 ./build_selhide_ddk.sh
#   SELHIDE_SRC=/workdir/selhide-popsicle OUTDIR=/workdir/out ./build_selhide_ddk.sh
#   KDIR=/path/to/kernel/build ./build_selhide_ddk.sh
#
# Outputs are copied to OUTDIR, defaulting to the current directory.

SELHIDE_SRC="${SELHIDE_SRC:-$(pwd)/selhide-popsicle}"
OUTDIR="${OUTDIR:-$(pwd)}"
ARCH="${ARCH:-arm64}"
LLVM="${LLVM:-1}"
KMI="${KMI:-${DDK_TARGET:-android16-6.12}}"
OUT_NAME="${OUT_NAME:-selhide-${KMI}.ko}"

log() {
    printf '[build_selhide_ddk] %s\n' "$*"
}

die() {
    printf '[build_selhide_ddk] ERROR: %s\n' "$*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

find_kdir() {
    if [ -n "${KDIR:-}" ]; then
        printf '%s\n' "$KDIR"
        return
    fi

    for d in \
        /workspace \
        /workspace/common \
        /android-kernel \
        /android-kernel/common \
        /kernel \
        /kernel/common \
        /common \
        /workdir/ack-android16-6.12 \
        /workdir/ack-android13-5.15
    do
        if [ -f "$d/Makefile" ] && [ -d "$d/include" ]; then
            printf '%s\n' "$d"
            return
        fi
    done

    # Last resort: a shallow search keeps startup cheap in DDK containers.
    found="$(find / -maxdepth 3 -type f -name Makefile 2>/dev/null \
        | sed 's#/Makefile$##' \
        | while IFS= read -r d; do
              [ -d "$d/include" ] && printf '%s\n' "$d" && break
          done)"
    [ -n "$found" ] && printf '%s\n' "$found"
}

prepare_src_copy() {
    src="$1"
    build_dir="$2"

    rm -rf "$build_dir"
    mkdir -p "$build_dir"

    # Copy only source inputs; skip previous Kbuild products.
    cp "$src"/Makefile "$build_dir"/
    cp "$src"/*.c "$build_dir"/
    cp "$src"/*.h "$build_dir"/ 2>/dev/null || true
    cp "$src"/*.S "$build_dir"/
}

print_env() {
    log "pwd=$(pwd)"
    log "SELHIDE_SRC=$SELHIDE_SRC"
    log "OUTDIR=$OUTDIR"
    log "OUT_NAME=$OUT_NAME"
    log "KMI=$KMI"
    log "DDK_TARGET=${DDK_TARGET:-}"
    log "KDIR=${KDIR:-}"
    log "PATH=$PATH"
    command -v ddk >/dev/null 2>&1 && log "ddk=$(command -v ddk)"
    command -v clang >/dev/null 2>&1 && log "clang=$(command -v clang)"
    command -v make >/dev/null 2>&1 && log "make=$(command -v make)"
}

copy_result() {
    build_dir="$1"
    dest="$OUTDIR/$OUT_NAME"

    [ -f "$build_dir/selhide.ko" ] || die "selhide.ko not produced in $build_dir"
    mkdir -p "$OUTDIR"
    cp "$build_dir/selhide.ko" "$dest"
    if command -v llvm-strip >/dev/null 2>&1; then
        llvm-strip -d "$dest" || true
    fi
    log "wrote $dest"
    if command -v modinfo >/dev/null 2>&1; then
        modinfo "$dest" 2>/dev/null | sed -n '/^filename:/p;/^version:/p;/^vermagic:/p;/^parm:/p'
    else
        strings "$dest" | grep -E '^(version|vermagic|parm|parmtype)=' || true
    fi
    if [ -x "${LOADER:-./kallsyms_init_module}" ]; then
        "${LOADER:-./kallsyms_init_module}" --dry-run "$dest" || true
    fi
}

build_with_make() {
    build_dir="$1"
    kdir="$2"

    log "building with make -C $kdir M=$build_dir"
    make -C "$kdir" M="$build_dir" ARCH="$ARCH" LLVM="$LLVM" KBUILD_MODPOST_WARN=1 clean modules
}

build_with_ddk() {
    build_dir="$1"

    log "building with ddk build, DDK_TARGET=$KMI"
    (
        cd "$build_dir"
        export DDK_TARGET="$KMI"
        ddk build
    )
}

main() {
    need_cmd make
    [ -d "$SELHIDE_SRC" ] || die "SELHIDE_SRC not found: $SELHIDE_SRC"
    [ -f "$SELHIDE_SRC/Makefile" ] || die "SELHIDE_SRC has no Makefile: $SELHIDE_SRC"
    print_env

    tmp="${TMPDIR:-/tmp}/selhide-ddk-build.$$"
    trap 'rm -rf "$tmp"' EXIT
    prepare_src_copy "$SELHIDE_SRC" "$tmp"

    if command -v ddk >/dev/null 2>&1 && [ "${FORCE_MAKE:-0}" != "1" ]; then
        if build_with_ddk "$tmp"; then
            copy_result "$tmp"
            exit 0
        fi
        log "ddk build failed; falling back to make -C KDIR if possible"
    fi

    kdir="$(find_kdir)"
    [ -n "$kdir" ] || die "could not find KDIR; set KDIR=/path/to/kernel/build"
    build_with_make "$tmp" "$kdir"
    copy_result "$tmp"
}

main "$@"
