package com.ghostlock.app.data.payload

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PayloadBridgeTest {
    @Test
    fun `only the validated find n5 build matches`() {
        assertTrue(PayloadBridge.isFindN5Kernel("6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k"))
        assertFalse(PayloadBridge.isFindN5Kernel("6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k"))
        assertFalse(PayloadBridge.isFindN5Kernel(""))
    }

    @Test
    fun `round parity alternates the payload`() {
        assertEquals(PayloadBridge.FanoutPayload, PayloadBridge.payloadForRound(1))
        assertEquals(PayloadBridge.RotatePayload, PayloadBridge.payloadForRound(2))
        assertEquals(PayloadBridge.FanoutPayload, PayloadBridge.payloadForRound(3))
        assertEquals(PayloadBridge.RotatePayload, PayloadBridge.payloadForRound(24))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `round numbers are one based`() {
        PayloadBridge.payloadForRound(0)
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
        assertNull(PayloadBridge.classify(""))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `plan rejects a panic gate below the fire gate`() {
        PayloadBridge.Plan(gateMilliCelsius = 60000, panicMilliCelsius = 51000)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `plan rejects zero rounds`() {
        PayloadBridge.Plan(rounds = 0)
    }

    @Test
    fun `plan defaults match the documented run`() {
        val plan = PayloadBridge.Plan()
        assertEquals(25L, plan.rounds.toLong())
        assertEquals(640L, plan.budgetSeconds.toLong())
        assertEquals(120L, plan.stallSeconds.toLong())
    }
}
