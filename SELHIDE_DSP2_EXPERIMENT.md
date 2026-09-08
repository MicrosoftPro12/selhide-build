# selhide DirtySepolicy 2.x Experiment

Current validated targets:

- Xiaomi popsicle, Android 16, kernel `6.12.23-android16-5-g75e9b1c7ae7c-abogki463945075-4k`
- Xiaomi corot, Android 14, kernel `5.15.123-android13-8-00045-g67e07e3a663f-ab11550397`
- Xiaomi renoir, Android 12, kernel `5.4.147-qgki-ga2bfd24da692`
- Module version: `p0.13-dirtysepolicy2-exp`

## What The Experiment Hooks

- `/sys/fs/selinux/access` via `write_op[SEL_ACCESS]`
- `/sys/fs/selinux/context` via `write_op[SEL_CONTEXT]`
- `/proc/self/attr/current` fallback via SELinux `setprocattr` LSM hook

The clean policy source is Magisk's backup at:

```text
/debug_ramdisk/.magisk/selinux/load
```

## One-Shot Test

Put these files in one directory on the Android host/root shell:

- `selhide-popsicle-android16-6.12-dsp2-exp.ko`
- `kallsyms_init_module`
- `test_selhide_dirtysepolicy2_popsicle.sh`

Run:

```sh
sh ./test_selhide_dirtysepolicy2_popsicle.sh
```

The log is written to the current directory.

Optional app launch:

```sh
RUN_APP=1 sh ./test_selhide_dirtysepolicy2_popsicle.sh
```

## Stress Test

```sh
ROUNDS=5 sh ./stress_selhide_dirtysepolicy2_popsicle.sh
```

Summarize logs:

```sh
sh ./summarize_selhide_dirtysepolicy2_logs.sh
```

## Current Acceptance Signals

A good log should include:

- `dry_run_exit=0`
- `load_exit=0`
- `phase0 success`
- `SEL_ACCESS passthrough hook installed`
- `SEL_CONTEXT clean hook installed`
- `setprocattr clean hook installed`
- `SEL_CONTEXT hidden dirty context -> -22`
- `setprocattr current hidden dirty context -> EINVAL`
- `rmmod_exit=0`
- all three hooks restored on unload

DirtySepolicy 2.0 APK should report no dirty sepolicy found.

## DirtySepolicy v2.2 Delta

Upstream release `v2.2` (2026-05-29) adds checks that are outside the currently
validated three-hook scope:

- It reads the five-word `/sys/fs/selinux/status` structure and validates
  `sequence`, `enforcing`, `policyload`, and `deny_unknown` against different
  expectations for kernels before and after 6.10.
- It reads the access response sequence number and requires `avdSeqNo=1`.
  SelHide currently initializes the synthetic clean-policy AVD sequence to
  zero, so the v2.2 check is expected to report this even when all v2.0 probes
  are hidden.

Supporting v2.2 therefore requires a separately tested status read hook plus a
synthetic AVD sequence fix. The existing 5.4, 5.15, and 6.12 v2.0 results must
not be represented as v2.2 compatibility.

## p0.13 Stability Note

The `20260518_144349` crash was an FPAC oops at
`selhide_write_access_impl+0x15c`, which mapped to the compiler-generated
`autiasp` epilogue on the `SEL_ACCESS` transaction path.

`p0.13` keeps `selhide_main.o` out of automatic PAC/SCS instrumentation, matching
the earlier `selhide_patch_memory.o` workaround. The KCFI landing contract is
still owned by the assembly wrappers and runtime-synced type IDs.

## p0.13 Stress Result

`stress_selhide_dirtysepolicy2_popsicle_app3.sh` completed three RUN_APP rounds
on popsicle with strict per-round dmesg windows:

- `stress_round_1_20260518_153111.txt`: `PASS`, `fatal=0`, `errors=0`
- `stress_round_2_20260518_153121.txt`: `PASS`, `fatal=0`, `errors=0`
- `stress_round_3_20260518_153131.txt`: `PASS`, `fatal=0`, `errors=0`

The initial stress wrapper reported `round_exit=1` because probe helper scratch
variables clobbered the main shell return variable. That script bug is fixed by
using `probe_rc` and `main_rc`; the round logs themselves had already completed
with `RESULT: PASS script completed`.

## Legacy 5.x Setprocattr Notes

Android 5.15 CFI kernels may store `selinux_setprocattr.cfi_jt` in the legacy
LSM hook list instead of the raw `selinux_setprocattr` address. Corot passed a
full DirtySepolicy 2.0 run after matching that jump-table target and restored
all hooks on unload.

Renoir's 5.4 LTO kernel gives the jump-table symbol a hash suffix:

```text
selinux_setprocattr$<hash>.cfi_jt
```

The Android runner discovers the exact name from `/proc/kallsyms` and passes it
through the `setprocattr_cfi_symbol` module parameter.

The first real hashed-symbol test panicked before any hook was installed. The
new symbol branch had called `p_kallsyms_lookup_name` directly, causing the 5.4
vendor CFI check to reject `kallsyms_lookup_name`. It now uses the existing
`selhide_call_kallsyms_lookup_name` assembly trampoline. Host disassembly
confirms the repaired branch has a direct relocation to that trampoline.

`build_selhide_ddk.sh` rejects source containing a direct
`p_kallsyms_lookup_name(...)` call so this failure mode cannot silently return.
The repaired Renoir module passed loader preflight, a two-second hook-only run,
and a full DirtySepolicy 2.0 run. The hashed CFI target was found as `kind=cfi_jt`,
all three hooks were installed, the app reported `OK`, and all hooks were
restored on unload. The tested module SHA-256 is
`a38eda9e78bfd2880ee81d9705086249f6eafceb451acd9407e293c2103abf7f`.

## GitHub Reproducibility Result

GitHub Actions run `34197943429` at commit `529a09e` completed both the
Android 16/6.12 DDK job and the Renoir Android 12/5.4 ACK job successfully.
The Renoir job independently downloaded and prepared ACK, cross-compiled the
module on an x86_64 hosted runner, verified its CFI entry symbols, and uploaded
the artifact.

The resulting `selhide-renoir-android12-5.4.147-qgki.ko` has SHA-256
`f08d9b31b017137fe522e2d2ab8bb3b4b6035fe4bd5a0e7a3b31b040ae0423ea`
and exact target vermagic
`5.4.147-qgki-ga2bfd24da692 SMP preempt mod_unload modversions aarch64`.
On the Renoir device it passed 45/45 loader symbol resolution, a two-second
hook-only run, and a full DirtySepolicy 2.0 query run. Magisk, `magisk_file`,
and `lsposed_file` context probes all took the hidden path; all three hooks
were restored and the module was absent after unload. Automated UI capture is
not available on this ROM because its `screencap` process crashes independently.
