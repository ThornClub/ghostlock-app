# Payload orchestration (CVE-2026-64560)

> Scope: `app/src/main/kotlin/com/ghostlock/app/data/payload/**`,
> `GhostlockUserService` payload primitives, `AndroidGhostlockRepository.runPayloadPath`.
> Authoritative state machine: `.trellis/tasks/10-28-n5-payload-kernel-support/design.md` D7.

---

## Why a separate path

The Find N5 build `6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k` already ships the rtmutex
fix, so the in-process pipeline cannot run there (`cve_2026_64560` backend is still a reserved,
unavailable id in `route/component_catalog.hpp`). On that kernel the exploit lives in a
self-contained payload (`libn5fanout.so` / `libn5rotate.so`) that performs its own race,
controlled write and credential patch.

GhostLock therefore has two execution paths:

| Kernel | Path |
| --- | --- |
| exact `uname -r` match in `kernel_profiles/index.conf` | native pipeline (`libghostlock.so`) |
| contains the payload marker `gc4127a25dcf3` | CVE-2026-64560 payload, driven from the app |

`KernelSupport.isSupported()` combines: builtin profile, imported offsets, payload-served kernel.
The payload marker is defined once, in `PayloadBridge.isFindN5Kernel`.

No `kernel_profiles/` entry is created for a payload-served kernel: every field of those profiles
(task_struct, offsets, route) only feeds the native pipeline, so writing one would be fabricated
data that nothing reads.

---

## Layering

| Layer | Location | Responsibility |
| --- | --- | --- |
| Decision (pure, no Android) | `data/payload/PayloadRoundDriver.kt` | round schedule, payload alternation, cooling gate, crash streak, result classification, spray health |
| Primitives (uid=shell) | `shizuku/GhostlockUserService.kt` | thermal read, stray payload kill, reboot, one payload round, KernelSU handover |
| Wiring | `data/AndroidGhostlockRepository.kt` | `PayloadDevice` implementation over the AIDL primitives, diagnostics export |
| Pure facts | `data/payload/PayloadBridge.kt` | payload names, markers, `Plan`, pending-signal gate |

The app process is `untrusted_app`: it cannot read `/sys/class/thermal`, `/proc/modules`, reboot,
or kill shell-uid processes. Everything privileged happens in the Shizuku UserService.

---

## AIDL primitives (transaction ids)

`destroy`=16777114, `runExploit`=2, `runPayload`=3, `runExploitAsManager`=4.

| Method | Id | Meaning of the return value |
| --- | --- | --- |
| `runPayload(rotate, budget, stall, gate, callback)` | 3 | one round on the current boot; `onComplete` 0=hold, 1=exited, 2=rejected, 3=stalled |
| `maxThermalMilliCelsius()` | 5 | hottest CPU zone, mC; 0 = unreadable |
| `killStrayPayloads()` | 6 | stray `n5fanout`/`n5rotate` processes left after the sweep |
| `rebootDevice()` | 7 | exit code of the `reboot` command (0 = accepted); shell has no CAP_SYS_BOOT |
| `handoverKernelSU(manager, callback)` | 8 | 0 only when `/proc/modules` shows `kernelsu ... Live` |

`destroy` keeps the reserved high id.

---

## Round semantics

One round = one payload process + one classification. The validated recipe needs several rounds:
a miss leaves the sprayed slab state dirty, so the next round starts on a freshly booted kernel.

- Payload alternation: odd rounds `fanout`, even rounds `rotate`.
- Cooling gate before each round: `exact` (≤ gate), `plateau-bypass` (no ≥2 C improvement inside a
  90 s window while still within gate+2 C), or `timeout` (abort the run).
- Panic abort: two consecutive samples ≥ `panicMilliCelsius` kill the payload and end the round as
  `HOTABORT`.
- Classification: `HOLD` marker → hold; `TARGET_PROFILE_GATE_FAIL` → reject (stop everything);
  stalled/exit → miss; binder gone after exit → crash.
- Crash streak ≥ 2: wait for `boot_id` to change and cool down to `rebootCoolMilliCelsius` before
  the next round, dropping the shortened quiet window.
- After a non-hold round with `rebootEachRound`: issue a reboot and wait for the boot id to change.

---

## KernelSU handover

Only after a hold. The root child lives inside the payload process, so the script is written to its
stdin and the markers are read back from the payload log:

```
setenforce 0; echo KSU_ENFORCE=$(getenforce)
chmod 755 ksud libadbroot
ksud late-load --kmi android15-6.6 --allow-shell   -> KSU_LATELOAD_RC
grep kernelsu /proc/modules        -> KSU_MODPROBE_DONE
ksud install --libadbroot ... --data-path /data/adb  -> KSU_INSTALL_RC
ksud soft-reboot                   -> KSU_SOFTREBOOT_RC
echo KSU_HANDOVER_DONE_MARK
```

Success is **only** `kernelsu ... Live` in `/proc/modules`. An insmod that worked followed by a
failed install returns 1 — the observed failure mode on this device is `shell` losing write access
to `/data/adb` once permissive is rolled back.

`ksud` / `libadbroot.so` are resolved from the installed KernelSU-family manager. The module is
loaded with `ksud late-load --kmi <KMI>`, the same call the native handoff uses, so no bundled
`kernelsu.ko` is required; when a `kernelsu.ko` happens to be present at `<filesDir>/kernelsu.ko`
or `/data/local/tmp/kernelsu.ko` the script falls back to `ksud insmod`. `KMI` is derived from
`uname -r` by `PayloadBridge.kmiFor` (`android15-6.6` here). Missing tools are reported as missing
instead of being simulated.

---

## Diagnostics

Every payload run writes, into the normal debug archive folder:

- `payload-run.txt` — plan, hold round, abort reason, per-round table (result, payload, gate, start
  and peak temperature, duration, quiet window, stray count, spray ratio) plus the temperature trace.
- `round-<n>.log` — the payload log tail of that round.

The fields mirror the toolbox `diag.txt`, which is the evidence format this path was validated with.

---

## Known limits

- If Shizuku does not come back after a reboot, the driver stops with `offline` instead of spinning.
- Whether SELinux returned to `Enforcing` cannot be checked from the app (no shell); the payload's
  own `STAGE8_ENV_GATE` is the authoritative gate.
- Module loading uses `ksud late-load`, so it depends on a KernelSU-family manager being installed
  and able to resolve the LKM for `android15-6.6`.
