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
text-patch helper now has a legacy nofault I/O path for 5.4-style kernels, but
the GitHub workflow still depends on available `ddk-min` container tags.

## Local fallback

Inside a DDK container:

```sh
KMI=android16-6.12 ./build_selhide_ddk.sh
```

Against a local Android common kernel tree:

```sh
KDIR=/path/to/common FORCE_MAKE=1 ./build_selhide_ddk.sh
```

For Android 12 / 5.4 qgki targets such as `5.4.147-qgki`, use a matching local
kernel build tree and exact target vermagic. A matching public `ddk-min`
`android12-5.4` image was not available when this note was written.

## Notes

- The `ddk-min` images currently used by KernelSU are `linux/amd64`. Run the
  GitHub workflow on the default x86_64 runner; do not try to run these images
  directly on Android/arm64 udocker unless qemu-user is configured.
- The package carries an `android16-6.12` SELinux private-header fallback under
  `selhide-popsicle/selinux-headers`. Kbuild still prefers headers from the DDK
  kernel tree when present, but the fallback avoids missing
  `security/selinux/include/security.h` in slim DDK images.
- The produced `.ko` still needs the existing staged loader/test path on device.
- This package intentionally excludes local build products, ACK checkouts,
  Magisk policy dumps, crash logs, and device-specific test output.
