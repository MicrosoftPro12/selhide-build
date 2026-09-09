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

## Guarded Magisk package

`build_magisk_module.sh` packages exact `uname -r` artifacts into an
experimental Magisk module. Installation never loads an LKM. Its `webroot`
panel uses the KernelSU-compatible root command bridge as the primary control
path; WebUI X provides the same bridge for Magisk. A timeout-bounded volume-key
Action remains the fallback. The root controller is also available directly:

After any KO, loader, or clean-policy change, the WebUI Autoload control first
runs the guarded trial. A successful trial must finish and unload before the
next press can enable boot loading. Controller error 60 means the current
identity has not passed that trial and `/data/adb/selhide/autoload` was
intentionally not created.

The WebUI follows the host WebView's system language on first launch and
supports a persistent English / Simplified Chinese switch in the header.

```sh
/data/adb/modules/selhide/bin/selhide_ctl.sh preflight
/data/adb/modules/selhide/bin/selhide_ctl.sh trial 60
/data/adb/modules/selhide/bin/selhide_ctl.sh enable-autoload
/data/adb/modules/selhide/bin/selhide_ctl.sh hiding-off
/data/adb/modules/selhide/bin/selhide_ctl.sh hiding-on
/data/adb/modules/selhide/bin/selhide_ctl.sh apply-mode-manual
/data/adb/modules/selhide/bin/selhide_ctl.sh apply-mode-sync
```

Every load first persists a panic marker. If it is not cleared during the same
boot, the next `post-fs-data` pass disables the Magisk module, removes autoload,
enters safe mode, and captures available pstore evidence. Trial authorization
is tied to hashes of the exact KO, loader and clean policy, so package or policy
updates require another trial. See `magisk-module/README.md` for recovery and
configuration details.

The loader and package builder reject Android 6.1+ artifacts unless the module
init and cleanup symbols carry the expected KCFI entry type IDs. This catches a
class of otherwise fatal modules that can pass vermagic and unresolved-symbol
checks but panic in `do_one_initcall()` before the module prints its first log.

`hiding-off` switches the loaded callbacks to original-policy pass-through via
the existing writable module parameter, without unloading. The apply list
defaults to continuously mirroring Magisk's denylist. Switching to manual mode
takes a fresh denylist snapshot and unlocks package add/remove controls in the
WebUI. Userspace resolves packages to Android appIds; `apply_filter=1` limits
clean-policy responses to those appIds across Android users. Shared-UID packages
are necessarily selected together. This path remains experimental until the
AppZygote caller identity has been traced on each supported kernel family.

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
- `kallsyms_init_module.c` is the staged KernelSU-style loader used by the test
  bundles. Its real-load guard now follows Android `same_magic()` behavior more
  closely: exact release is accepted, and non-exact release is accepted only
  when the module has modversions and its vermagic suffix matches a reference
  module from the running device.
- `check_selhide_vermagic_guard.sh` is safe to run first on Android host/root
  shell. It never calls `init_module(2)`; it only reports exact/KMI-compatible
  status through `kallsyms_init_module --check-vermagic`, then optionally runs
  the dry-run symbol resolver.
- If a device has no readable `/vendor/lib/modules` or similar reference `.ko`,
  `SELHIDE_REFERENCE_VERMAGIC='...'` or a local `reference_vermagic.txt` can
  provide a known device vermagic for the same suffix check. User-supplied
  references must match the running `uname -r` unless
  `ALLOW_REFERENCE_RELEASE_MISMATCH=YES` is set, and this is deliberately
  narrower than `ALLOW_UNSAFE_MODULE_LOAD=YES`: modversions and suffix equality
  are still required.
- `build_selhide_ddk.sh` removes `.BTF/.BTF.ext` by default (`STRIP_BTF=1`).
  This keeps test artifacts away from module-BTF parser failures such as
  `BPF: Invalid name_offset`; set `STRIP_BTF=0` only when intentionally
  comparing with KernelSU-style unstripped artifacts.
- `selhide-popsicle` uses normal `module_init/module_exit` by default so
  CFI-enabled DDK builds emit `__cfi_jt_init_module` and
  `__cfi_jt_cleanup_module`, matching KernelSU's LKM entry shape.
- Local ACK / `FORCE_MAKE=1` builds whose compiler does not emit KCFI landing
  pads need assembly init/exit wrappers; `build_selhide_ddk.sh` now enables
  `SELHIDE_ASM_INIT=1` automatically for local 6.x fallback builds. Direct
  Makefile users must set it themselves, otherwise KCFI kernels can panic in
  `do_one_initcall` before `phase0 loading` is printed.
- On-device testing is intended to use the one-click Android shell wrappers:
  `run_popsicle_local_smoke.sh` for one conservative load/probe/unload cycle,
  or `run_popsicle_local_app_stress.sh` for three DirtySepolicy APK rounds.
- This package intentionally excludes local build products, ACK checkouts,
  Magisk policy dumps, crash logs, and device-specific test output.
