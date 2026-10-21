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
 * GhostLock owns only the decisions around it: which payload a round uses, when
 * a round stops, and how a payload line maps to an outcome. The payload owns
 * the kernel primitive; GhostLock must never claim a write it did not verify.
 */
object PayloadBridge {
    /** Kernel release fragment of the only build this bridge is validated for. */
    const val FindN5KernelMarker = "gc4127a25dcf3"

    /** Odd rounds: timer fan-out variant. */
    const val FanoutPayload = "libn5fanout.so"

    /** Even rounds: timer slot rotation variant. */
    const val RotatePayload = "libn5rotate.so"

    /** Payload reached an interactive root child; this is the only success marker. */
    const val HoldMarker = "ROOT_CHILD_HOLD_PASS"

    /** Payload refused this device; another round cannot change that. */
    const val RejectMarker = "TARGET_PROFILE_GATE_FAIL"

    /** How one payload round ended. */
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

    /** One run: round count, per-round budget, silence limit and heat gates. */
    data class Plan(
        val rounds: Int = 25,
        val budgetSeconds: Int = 640,
        val stallSeconds: Int = 120,
        val gateMilliCelsius: Int = 51300,
        val panicMilliCelsius: Int = 60000,
    ) {
        init {
            require(rounds > 0) { "rounds must be positive" }
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
     * Payload for a 1-based round. Alternating the two variants is what gives a
     * round a second chance after a miss; the choice is round parity, never
     * kernel metadata.
     */
    fun payloadForRound(round: Int): String {
        require(round > 0) { "rounds are 1-based" }
        return if (round % 2 == 0) RotatePayload else FanoutPayload
    }

    /** Terminal outcome carried by [line], or null for a plain progress line. */
    fun classify(line: String): Outcome? = when {
        line.contains(HoldMarker) -> Outcome.Hold
        line.contains(RejectMarker) -> Outcome.Rejected
        else -> null
    }

    /** True when the round must stop immediately instead of burning its budget. */
    fun isTerminal(outcome: Outcome?): Boolean =
        outcome == Outcome.Hold || outcome == Outcome.Rejected
}
