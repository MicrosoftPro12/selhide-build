# SelHide Magisk Module Shell

This package is deliberately conservative while kernel coverage is still being
expanded. Installing or updating it never loads an LKM. The Magisk action also
runs only a load-free preflight.

## Panic Guard

Every real load atomically creates `/data/adb/selhide/load_pending` first. A
successful load clears it only after the configured stability window, or after
a trial unloads cleanly. If the kernel panics before that checkpoint, the marker
survives the reboot. On the next boot `post-fs-data.sh` creates the module's
`disable` flag, removes autoload, records the guard, and enters persistent safe
mode before another load can be attempted.

This cannot execute code during a panic. It prevents the following boot from
repeating the same load, which is the useful self-recovery point.

Boot autoload waits for `sys.boot_completed=1` plus a configurable delay. If
Android does not complete boot within three minutes, no load is attempted. On
guard recovery, available pstore files are copied under
`/data/adb/selhide/recovery_*` before the module disables itself.

A successful trial is bound to the exact kernel release plus hashes of the KO,
loader and clean policy. Updating any of them invalidates autoload until another
trial passes. Watchers also carry a unique guard ID, so an older timer cannot
clear a newer load's panic marker.

On Android 6.1 and newer kernels, preflight also verifies the KCFI words before
`init_module` and `cleanup_module`. Missing or incorrect entry metadata is
rejected before the loader can call `init_module(2)`.

## Controller

Run as root after installation:

```sh
/data/adb/modules/selhide/bin/selhide_ctl.sh status
/data/adb/modules/selhide/bin/selhide_ctl.sh preflight
/data/adb/modules/selhide/bin/selhide_ctl.sh trial 60
/data/adb/modules/selhide/bin/selhide_ctl.sh enable-autoload
```

During `trial`, open DirtySepolicy before the timer expires. The module unloads
at the end and records `trial_passed` only when unload succeeds.

`import-denylist` writes `/data/adb/selhide/apply-list.txt`. This is currently
metadata for the planned policy UI. The LKM hook remains global; per-app kernel
enforcement must not be claimed until a cross-kernel-safe caller identity path
is implemented.

## Recovery

After a guarded panic, Magisk shows the module as disabled. Re-enabling it in a
manager is not enough to resume autoload because `/data/adb/selhide/safe_mode`
also remains. Inspect `recovered_guard_*.txt` and diagnostics before running:

```sh
/data/adb/modules/selhide/bin/selhide_ctl.sh clear-safe-mode
```

Autoload remains off until explicitly enabled again.
