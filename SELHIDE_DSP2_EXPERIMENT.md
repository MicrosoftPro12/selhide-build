# selhide DirtySepolicy 2.x Experiment

Current validated target:

- Device: Xiaomi popsicle
- Android: 16 / Android 16 GKI profile
- Runtime kernel: `6.12.23-android16-5-g75e9b1c7ae7c-abogki463945075-4k`
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
