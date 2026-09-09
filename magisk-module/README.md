# SelHide Magisk Module Shell

This package is deliberately conservative while kernel coverage is still being
expanded. Installing or updating it never loads an LKM. A `webroot` control
panel is the primary interface in KernelSU Manager or a compatible Magisk host
such as WebUI X. It reads live state through the host's root command bridge and
does not run a separate receiver daemon.

The WebUI Autoload control is deliberately two-stage after a KO, loader, or
clean-policy change. Its first press starts the guarded trial; open
DirtySepolicy while that command is running. After the trial unloads
successfully, press Autoload again to create the boot marker. Error code 60
means this exact runtime identity has not completed that trial, so no autoload
marker was written.

On first launch, the WebUI selects English or Simplified Chinese from the
system WebView language. The header switch stores an explicit user choice when
the host permits WebView local storage.

If Android's low-level `cmd package` query fails while resolving the apply
list, the controller retries through `pm`. A failure of both paths blocks the
load before arming the panic guard and records their return codes in
`/data/adb/selhide/selhide.log`.

The Magisk Action remains a volume-key fallback:

1. Before validation, press Volume Up to run preflight and a timed guarded
   trial. Volume Down cancels without loading.
2. After that exact runtime identity passes, press Volume Up to enable boot
   autoload. Volume Down cancels, and the LKM is not loaded immediately.
3. When autoload is enabled or the LKM is loaded, press Volume Up to switch
   between hiding and pass-through without unloading. Volume Down disables
   autoload and unloads.

Each prompt times out after 20 seconds and makes no change. The timeout can be
overridden with `ACTION_KEY_TIMEOUT_SECONDS` in the persistent config file.

Persistent safe mode is never cleared by Action. In particular, Action refuses
to retry the same artifact associated with an uncleared panic guard.

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
/data/adb/modules/selhide/bin/selhide_ctl.sh hiding-off
/data/adb/modules/selhide/bin/selhide_ctl.sh hiding-on
/data/adb/modules/selhide/bin/selhide_ctl.sh apply-mode-manual
/data/adb/modules/selhide/bin/selhide_ctl.sh apply-add com.example.app
/data/adb/modules/selhide/bin/selhide_ctl.sh apply-mode-sync
```

During `trial`, open DirtySepolicy before the timer expires. The module unloads
at the end and records `trial_passed` only when unload succeeds.

`hiding-off` leaves the hooks attached but changes all three callbacks to
pass-through mode through the existing writable `clean_access` module
parameter. `hiding-on` resumes clean-policy responses immediately. The desired
mode is persistent and is applied to later manual or boot loads; guarded trials
always test with hiding enabled.

## Apply List

The default `sync` mode continuously mirrors Magisk's denylist while SelHide is
loaded. The WebUI treats the list as read-only in this mode. `apply-mode-manual`
takes a fresh denylist snapshot, stops the sync watcher, and unlocks package
add/remove controls. Returning to `apply-mode-sync` discards manual divergence
and immediately refreshes from Magisk again.

Packages are resolved to Android appIds before each load and whenever the list
changes. The LKM then returns the clean policy only for selected appIds. This
covers the same application across Android users, but also means packages with
a shared UID are selected together. Process-level Magisk denylist entries are
collapsed to their package because a stable process-name filter is not used in
the kernel hook. The appId filter is still experimental until AppZygote caller
identity is confirmed on every supported kernel family.

Persistent files are under `/data/adb/selhide`: `apply-mode`, `apply-list.txt`,
and the generated `apply-appids.txt`. Sync runs every 30 seconds by default;
`APPLY_SYNC_SECONDS` in `config.conf` can change the interval, with a minimum of
five seconds.

## Recovery

After a guarded panic, Magisk shows the module as disabled. Re-enabling it in a
manager is not enough to resume autoload because `/data/adb/selhide/safe_mode`
also remains. Inspect `recovered_guard_*.txt` and diagnostics before running:

```sh
/data/adb/modules/selhide/bin/selhide_ctl.sh clear-safe-mode
```

Autoload remains off until explicitly enabled again.
