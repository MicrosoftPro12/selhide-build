# selhide DDK action package

This package is a minimal GitHub Actions repo for building the current
`selhide-popsicle` kernel module inside `ghcr.io/ylarod/ddk-min`.

## Use

1. Upload this directory as a GitHub repository.
2. Open `Actions -> Build selhide DDK module`.
3. Run the workflow manually.
4. Download the `.ko` from the workflow artifact.

Default target:

```text
android16-6.12 / DDK release 20260313
```

The source currently targets the popsicle Android 16 / 6.12 implementation. The
workflow exposes older KMI choices for compile experiments, but those are not
runtime-compatible until the corresponding source path is implemented.

## Local fallback

Inside a DDK container:

```sh
KMI=android16-6.12 ./build_selhide_ddk.sh
```

Against a local Android common kernel tree:

```sh
KDIR=/path/to/common FORCE_MAKE=1 ./build_selhide_ddk.sh
```

## Notes

- The `ddk-min` images currently used by KernelSU are `linux/amd64`. Run the
  GitHub workflow on the default x86_64 runner; do not try to run these images
  directly on Android/arm64 udocker unless qemu-user is configured.
- The produced `.ko` still needs the existing staged loader/test path on device.
- This package intentionally excludes local build products, ACK checkouts,
  Magisk policy dumps, crash logs, and device-specific test output.
