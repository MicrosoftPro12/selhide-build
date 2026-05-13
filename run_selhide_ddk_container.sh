#!/usr/bin/env bash
set -euo pipefail

# Launch a DDK container and run build_selhide_ddk.sh inside it.
#
# Works with docker/podman when available. udocker support is best-effort and
# depends on the host Termux/proot setup.
#
# Usage:
#   KMI=android16-6.12 ./run_selhide_ddk_container.sh
#   ENGINE=udocker KMI=android13-5.15 ./run_selhide_ddk_container.sh

KMI="${KMI:-android16-6.12}"
DDK_RELEASE="${DDK_RELEASE:-20260313}"
IMAGE="${IMAGE:-ghcr.io/ylarod/ddk-min:${KMI}-${DDK_RELEASE}}"
WORKDIR_HOST="${WORKDIR_HOST:-$(pwd)}"
OUTDIR="${OUTDIR:-/workdir/out-ddk}"
SELHIDE_SRC="${SELHIDE_SRC:-/workdir/selhide-popsicle}"
OUT_NAME="${OUT_NAME:-selhide-${KMI}.ko}"
ENGINE="${ENGINE:-}"
CHECK_IMAGE_ARCH="${CHECK_IMAGE_ARCH:-1}"
PLATFORM="${PLATFORM:-}"
SAFE_KMI="$(printf '%s' "$KMI" | tr -c 'A-Za-z0-9_' '_')"
SAFE_REL="$(printf '%s' "$DDK_RELEASE" | tr -c 'A-Za-z0-9_' '_')"

log() {
    printf '[run_selhide_ddk_container] %s\n' "$*"
}

die() {
    printf '[run_selhide_ddk_container] ERROR: %s\n' "$*" >&2
    exit 1
}

normalize_arch() {
    case "$1" in
        amd64|x86_64) printf 'amd64\n' ;;
        arm64|aarch64) printf 'arm64\n' ;;
        armv7*|armhf) printf 'arm\n' ;;
        *) printf '%s\n' "$1" ;;
    esac
}

qemu_for_arch() {
    case "$(normalize_arch "$1")" in
        amd64) command -v qemu-x86_64-static 2>/dev/null || command -v qemu-x86_64 2>/dev/null ;;
        arm64) command -v qemu-aarch64-static 2>/dev/null || command -v qemu-aarch64 2>/dev/null ;;
        arm) command -v qemu-arm-static 2>/dev/null || command -v qemu-arm 2>/dev/null ;;
        *) return 1 ;;
    esac
}

detect_ghcr_platforms() {
    image="$1"
    command -v python3 >/dev/null 2>&1 || return 2
    python3 - "$image" <<'PY'
import json
import sys
import urllib.request

image = sys.argv[1]
if not image.startswith("ghcr.io/"):
    sys.exit(2)

ref = image[len("ghcr.io/"):]
if "@" in ref:
    repo, tag = ref.split("@", 1)
else:
    slash = ref.rfind("/")
    colon = ref.rfind(":")
    if colon > slash:
        repo, tag = ref[:colon], ref[colon + 1:]
    else:
        repo, tag = ref, "latest"

accept = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])

try:
    with urllib.request.urlopen(
        f"https://ghcr.io/token?scope=repository:{repo}:pull", timeout=30
    ) as resp:
        token = json.load(resp)["token"]

    req = urllib.request.Request(
        f"https://ghcr.io/v2/{repo}/manifests/{tag}",
        headers={"Authorization": f"Bearer {token}", "Accept": accept},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        manifest = json.load(resp)

    platforms = []
    if "manifests" in manifest:
        for item in manifest["manifests"]:
            platform = item.get("platform") or {}
            os_name = platform.get("os")
            arch = platform.get("architecture")
            if os_name and arch:
                platforms.append(f"{os_name}/{arch}")
    else:
        digest = (manifest.get("config") or {}).get("digest")
        if digest:
            req = urllib.request.Request(
                f"https://ghcr.io/v2/{repo}/blobs/{digest}",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                config = json.load(resp)
            os_name = config.get("os")
            arch = config.get("architecture")
            if os_name and arch:
                platforms.append(f"{os_name}/{arch}")

    if not platforms:
        sys.exit(2)
    print(",".join(platforms))
except Exception as exc:
    print(f"detect_failed:{exc}", file=sys.stderr)
    sys.exit(2)
PY
}

preflight_image_arch() {
    [ "$CHECK_IMAGE_ARCH" = "1" ] || return 0

    host_arch="$(normalize_arch "$(uname -m)")"
    log "host_arch=$host_arch"

    platforms="$(detect_ghcr_platforms "$IMAGE" 2>/dev/null || true)"
    if [ -z "$platforms" ]; then
        log "image_platforms=unknown (skipping preflight)"
        return 0
    fi
    log "image_platforms=$platforms"

    if printf '%s' "$platforms" | tr ',' '\n' | awk -F/ '{print $2}' \
        | while IFS= read -r arch; do [ "$(normalize_arch "$arch")" = "$host_arch" ] && exit 0; done
    then
        return 0
    fi

    target_arch="$(printf '%s' "$platforms" | tr ',' '\n' | awk -F/ 'NR == 1 {print $2}')"
    target_arch="$(normalize_arch "$target_arch")"
    if qemu_path="$(qemu_for_arch "$target_arch")"; then
        log "qemu=$qemu_path"
        log "cross-arch udocker may be very slow and may still fail under nested proot"
        return 0
    fi

    die "image is $platforms but host is linux/$host_arch; qemu for $target_arch is not available. Run this DDK container on an x86_64 Linux/docker host, install qemu-user for udocker, or use FORCE_MAKE=1 ./build_selhide_ddk.sh against the local ACK tree instead."
}

pick_engine() {
    if [ -n "$ENGINE" ]; then
        printf '%s\n' "$ENGINE"
        return
    fi
    for e in docker podman udocker; do
        if command -v "$e" >/dev/null 2>&1; then
            printf '%s\n' "$e"
            return
        fi
    done
}

engine="$(pick_engine)"
[ -n "$engine" ] || {
    echo "No docker/podman/udocker found. Run ./build_selhide_ddk.sh inside a DDK container instead." >&2
    exit 1
}

log "engine=$engine"
log "image=$IMAGE"
log "workdir=$WORKDIR_HOST"
log "outdir=$OUTDIR"
[ -n "$PLATFORM" ] && log "platform=$PLATFORM"

case "$engine" in
    docker|podman)
        platform_args=()
        [ -z "$PLATFORM" ] || platform_args=(--platform "$PLATFORM")
        "$engine" run --rm --privileged "${platform_args[@]}" \
            -v "$WORKDIR_HOST:/workdir" \
            -w /workdir \
            -e KMI="$KMI" \
            -e DDK_TARGET="$KMI" \
            -e SELHIDE_SRC="$SELHIDE_SRC" \
            -e OUTDIR="$OUTDIR" \
            -e OUT_NAME="$OUT_NAME" \
            "$IMAGE" \
            bash -lc './build_selhide_ddk.sh'
        ;;
    udocker)
        preflight_image_arch
        # udocker container names are stricter than docker/podman names on
        # some versions; avoid dots, dashes, and colons entirely.
        cname="selhide_ddk_${SAFE_KMI}_${SAFE_REL}"
        log "udocker_name=$cname"
        udocker_cmd=(udocker)
        if [ "$(id -u)" = "0" ]; then
            udocker_cmd+=(--allow-root)
        fi
        platform_args=()
        [ -z "$PLATFORM" ] || platform_args=(--platform="$PLATFORM")
        # `run --name=... --pull=reuse image` reuses an existing named
        # container or creates it from the image if missing. This avoids
        # version differences around `udocker inspect` / `udocker ps`.
        "${udocker_cmd[@]}" run \
            --name="$cname" \
            --pull=reuse \
            --volume="$WORKDIR_HOST:/workdir" \
            --workdir=/workdir \
            --env="KMI=$KMI" \
            --env="DDK_TARGET=$KMI" \
            --env="SELHIDE_SRC=$SELHIDE_SRC" \
            --env="OUTDIR=$OUTDIR" \
            --env="OUT_NAME=$OUT_NAME" \
            "${platform_args[@]}" \
            "$IMAGE" \
            bash -lc './build_selhide_ddk.sh'
        ;;
    *)
        echo "unsupported engine: $engine" >&2
        exit 1
        ;;
esac
