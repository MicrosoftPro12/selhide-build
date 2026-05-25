# selhide DDK action package

This package is a minimal GitHub Actions repo for building the current
`selhide-popsicle` kernel module through either `ghcr.io/ylarod/ddk-min`
or a prepared Android common kernel tree.

## Use

1. Upload this directory as a GitHub repository.
2. Open `Actions -> Build selhide LKM matrix` for the reusable matrix flow, or
   `Actions -> Build selhide DDK module` for the older all-in-one experiment.
3. Run the workflow manually.
4. Download the `.ko` from the workflow artifact.

The older all-in-one workflow also runs on pushes to the `experiment` and
`experimental/**` branches. Push builds target popsicle and allow the local
Kbuild fallback inside the DDK container so artifacts keep flowing while the
experiment is moving. Manual workflow runs can set `require_ddk=1` when the goal
is strict DDK frontend validation.

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

For renoir / Android 12 / 5.4.147-qgki, run the workflow manually with
`kmi=android12-5.4`. That path downloads the Android common
`android12-5.4.147_r00` source archive, applies
`configs/renoir-5.4.147-qgki-ga2bfd24da692.config`, prepares the tree, and
builds `selhide-renoir-android12-5.4.147-qgki.ko`.

## Reusable GitHub Actions

The KernelSU-style LKM flow is split into small reusable workflows:

- `.github/workflows/build-selhide-lkm.yml` is the matrix entry point. It builds
  KernelSU-style DDK KMI targets from `android12-5.10` through `android16-6.12`
  and can also include checked-in ACK/Kbuild fallback targets.
- `.github/workflows/ddk-selhide-lkm.yml` builds one DDK-backed KMI target using
  `ghcr.io/ylarod/ddk-min:<kmi>-<release>`.
- `.github/workflows/ack-selhide-lkm.yml` builds one source-archive-backed
  target from a kernel archive URL plus a checked-in `.config`; renoir
  `android12-5.4.147-qgki` is the first configured fallback target.

## Notes

- The `ddk-min` images currently used by KernelSU are `linux/amd64`. Run the
  GitHub workflow on the default x86_64 runner; do not try to run these images
  directly on Android/arm64 udocker unless qemu-user is configured.
- The package carries an `android16-6.12` SELinux private-header fallback under
  `selhide-popsicle/selinux-headers`. Kbuild still prefers headers from the DDK
  kernel tree when present, but the fallback avoids missing
  `security/selinux/include/security.h` in slim DDK images.
- The produced `.ko` still needs the existing staged loader/test path on device.
- On-device testing is intended to use the one-click Android shell wrappers:
  `run_popsicle_local_smoke.sh` for one conservative load/probe/unload cycle,
  or `run_popsicle_local_app_stress.sh` for three DirtySepolicy APK rounds.
- This package intentionally excludes local build products, ACK checkouts,
  Magisk policy dumps, crash logs, and device-specific test output.
