package com.ghostlock.app.data.payload

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PayloadBridgeTest {
    private val deviceLimits = """
        Limit                     Soft Limit           Hard Limit           Units
        Max processes             41381                41381                processes
        Max pending signals       41381                41381                signals
        Max msgqueue size         819200               819200               bytes
    """.trimIndent()

    @Test
    fun `only the validated find n5 build matches`() {
        assertTrue(PayloadBridge.isFindN5Kernel("6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k"))
        assertFalse(PayloadBridge.isFindN5Kernel("6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k"))
        assertFalse(PayloadBridge.isFindN5Kernel(""))
    }

    @Test
    fun `payload variant is chosen by the caller`() {
        assertEquals(PayloadBridge.FanoutPayload, PayloadBridge.payloadFor(rotate = false))
        assertEquals(PayloadBridge.RotatePayload, PayloadBridge.payloadFor(rotate = true))
    }

    @Test
    fun `hold and reject lines are terminal`() {
        assertEquals(
            PayloadBridge.Outcome.Hold,
            PayloadBridge.classify("[+] ROOT_CHILD_HOLD_PASS child=1234 uid=0 context=shell"),
        )
        assertEquals(
            PayloadBridge.Outcome.Rejected,
            PayloadBridge.classify("[-] TARGET_PROFILE_GATE_FAIL fingerprint=OPPO/PKH110"),
        )
        assertTrue(PayloadBridge.isTerminal(PayloadBridge.Outcome.Hold))
        assertTrue(PayloadBridge.isTerminal(PayloadBridge.Outcome.Rejected))
        assertFalse(PayloadBridge.isTerminal(PayloadBridge.Outcome.Exited))
        assertFalse(PayloadBridge.isTerminal(PayloadBridge.Outcome.Stalled))
        assertFalse(PayloadBridge.isTerminal(null))
    }

    @Test
    fun `progress lines are not terminal`() {
        assertNull(PayloadBridge.classify("[*] PIPE_BIND_PASS addr=0xffff index=3 len=4096"))
        assertNull(PayloadBridge.classify("[-] ATTEMPT_MISS attempt=7"))
        assertNull(PayloadBridge.classify("[-] PREFLIGHT_PASS profile=pkh110-f07-2070"))
        assertNull(PayloadBridge.classify(""))
    }

    @Test
    fun `plan rejects a panic gate below the fire gate`() {
        val failed = runCatching {
            PayloadBridge.Plan(gateMilliCelsius = 60000, panicMilliCelsius = 51000)
        }
        assertTrue(failed.isFailure)
    }

    @Test
    fun `plan rejects non positive budgets`() {
        assertTrue(runCatching { PayloadBridge.Plan(budgetSeconds = 0) }.isFailure)
        assertTrue(runCatching { PayloadBridge.Plan(stallSeconds = 0) }.isFailure)
    }

    @Test
    fun `plan defaults match the validated recipe`() {
        val plan = PayloadBridge.Plan()
        assertEquals(900, plan.budgetSeconds)
        assertEquals(20, plan.stallSeconds)
        assertEquals(58000, plan.gateMilliCelsius)
        assertEquals(75000, plan.panicMilliCelsius)
    }

    @Test
    fun `signal ceiling is read from proc limits`() {
        assertEquals(41381, PayloadBridge.maxPendingSignals(deviceLimits))
        assertEquals(0, PayloadBridge.maxPendingSignals(""))
        assertEquals(0, PayloadBridge.maxPendingSignals("Max processes 1 1 processes"))
    }

    @Test
    fun `timer goal fits under the device ceiling`() {
        assertTrue(PayloadBridge.timerBudgetFits(deviceLimits))
    }

    @Test
    fun `timer goal above the ceiling is refused`() {
        val tight = deviceLimits.replace("Max pending signals       41381", "Max pending signals       30000")
        assertFalse(PayloadBridge.timerBudgetFits(tight))
    }

    @Test
    fun `unreadable limits are refused rather than assumed fine`() {
        assertFalse(PayloadBridge.timerBudgetFits(""))
    }

    @Test
    fun `timer goal matches the validated payload build`() {
        // The 40000 build reaches the spray target under the 41381 ceiling; the
        // older 55478 build could never fill it and only produced misses.
        assertEquals(40000, PayloadBridge.TimerGoal)
    }
}
