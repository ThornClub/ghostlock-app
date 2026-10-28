package com.ghostlock.app.data.payload

import com.ghostlock.app.data.payload.PayloadRoundDriver.Clock
import com.ghostlock.app.data.payload.PayloadRoundDriver.CoolGate
import com.ghostlock.app.data.payload.PayloadRoundDriver.PayloadDevice
import com.ghostlock.app.data.payload.PayloadRoundDriver.RoundResult
import com.ghostlock.app.data.payload.PayloadRoundDriver.RoundSignals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 轮次驱动的纯逻辑测试: 载荷交替、冷却三态、连续崩溃调度、结果判定、喷堆解析。
 * 假设备与假时钟让整条编排在毫秒级跑完, 不碰 Android 也不睡真的秒。
 */
class PayloadRoundDriverTest {
    private val clock = FakeClock()

    private fun driver(
        plan: PayloadBridge.Plan,
        device: FakeDevice,
        onRound: (PayloadRoundDriver.RoundRecord) -> Unit = {},
    ) = PayloadRoundDriver(plan, device, clock, onRound)

    @Test
    fun `odd rounds use fanout and even rounds use rotate`() {
        val device = FakeDevice()
        val plan = PayloadBridge.Plan(rounds = 3, rebootEachRound = false)
        driver(plan, device).run()

        assertEquals(listOf(false, true, false), device.rotateFlags)
        assertEquals(
            listOf("libn5fanout.so", "libn5rotate.so", "libn5fanout.so"),
            device.rotateFlags.map(PayloadBridge::payloadFor),
        )
    }

    @Test
    fun `cooling passes immediately when the sample is already under the gate`() {
        val device = FakeDevice().apply { temperature = 55_000 }
        assertEquals(CoolGate.Exact, driver(PayloadBridge.Plan(), device).awaitCooling(58_000, 300))
        assertTrue(clock.sleeps.isEmpty())
    }

    @Test
    fun `plateau bypass releases when the heat stops improving inside the margin`() {
        /* 59.5 C 高于 58 C 门限但落在 +2 C 容差内, 且 90 s 内没有 2 C 降幅 -> 平台期放行。 */
        val device = FakeDevice().apply { temperature = 59_500 }
        val gate = driver(PayloadBridge.Plan(), device).awaitCooling(58_000, 300)

        assertEquals(CoolGate.PlateauBypass, gate)
        assertTrue("should wait at least one plateau window", clock.now >= 90_000L)
        assertTrue("should stop before the cool timeout", clock.now < 300_000L)
    }

    @Test
    fun `cooling times out when the heat never enters the margin`() {
        val device = FakeDevice().apply { temperature = 70_000 }
        val gate = driver(PayloadBridge.Plan(), device).awaitCooling(58_000, 120)

        assertEquals(CoolGate.Timeout, gate)
        assertTrue(clock.now >= 120_000L)
    }

    @Test
    fun `two consecutive crashes force a full reset instead of a quick retry`() {
        val device = FakeDevice().apply {
            signals = RoundSignals(onlineAfterExit = false)
            temperature = 50_000
        }
        val records = mutableListOf<PayloadRoundDriver.RoundRecord>()
        val plan = PayloadBridge.Plan(rounds = 3, crashStreakForFullReset = 2)

        val summary = driver(plan, device) { records.add(it) }.run()

        assertEquals(List(3) { RoundResult.Crash }, records.map { it.result })
        /* 第 1 次崩只等设备回来; 第 2、3 次崩都已经在 streak 阈值以上, 每次都要全量重置。 */
        assertEquals(1, device.onlineWaits)
        assertEquals("full reset waits for boot_completed", 2, device.bootWaits)
        assertNull("no hold in this run", summary.holdRound)
    }

    @Test
    fun `a miss reboots the round and shortens the next quiet window`() {
        val device = FakeDevice()
        val records = mutableListOf<PayloadRoundDriver.RoundRecord>()
        val plan = PayloadBridge.Plan(rounds = 2, rebootEachRound = true)

        driver(plan, device) { records.add(it) }.run()

        assertEquals(1, device.reboots)
        assertEquals(plan.quietSeconds, records.first().quietSeconds)
        assertEquals(plan.fastQuietSeconds, records.last().quietSeconds)
    }

    @Test
    fun `a hold ends the run without rebooting`() {
        val device = FakeDevice().apply { signals = RoundSignals(sawHold = true) }
        val plan = PayloadBridge.Plan(rounds = 5)

        val summary = driver(plan, device).run()

        assertEquals(1, summary.holdRound)
        assertEquals(1, summary.records.size)
        assertFalse(summary.aborted)
        assertEquals(0, device.reboots)
    }

    @Test
    fun `a reject stops the whole run at once`() {
        val device = FakeDevice().apply { signals = RoundSignals(sawReject = true) }
        val summary = driver(PayloadBridge.Plan(rounds = 5), device).run()

        assertTrue(summary.aborted)
        assertEquals("rejected", summary.abortReason)
        assertEquals(1, summary.records.size)
        assertEquals(0, device.reboots)
    }

    @Test
    fun `classification covers every payload signal`() {
        val subject = driver(PayloadBridge.Plan(), FakeDevice())

        assertEquals(RoundResult.Hold, subject.classify(RoundSignals(sawHold = true)))
        assertEquals(RoundResult.Rejected, subject.classify(RoundSignals(sawReject = true)))
        assertEquals(RoundResult.HotAbort, subject.classify(RoundSignals(sawHotAbort = true)))
        assertEquals(RoundResult.Miss, subject.classify(RoundSignals(stalled = true)))
        assertEquals(RoundResult.Crash, subject.classify(RoundSignals(onlineAfterExit = false)))
        assertEquals(RoundResult.Miss, subject.classify(RoundSignals()))
    }

    @Test
    fun `spray health reports the timer gap and the signal ceiling errno`() {
        val tail = """
            RACE_CONFIG batch=1 timer_goal=40000 exec_repeats=4
            LANE_DONE sequence=7 timers=39000 deleted=39000 errors=0 create_errno=11
        """.trimIndent()

        val health = PayloadRoundDriver.sprayHealth(tail)!!
        assertEquals(40_000, health.timerGoal)
        assertEquals(39_000, health.timers)
        assertTrue(health.short)
        assertTrue(health.hitSignalCeiling)
    }

    @Test
    fun `spray health is null without lane bookkeeping`() {
        assertNull(PayloadRoundDriver.sprayHealth(""))
        assertNull(PayloadRoundDriver.sprayHealth("RACE_CONFIG timer_goal=40000"))
    }

    private class FakeClock(startMillis: Long = 0) : Clock {
        var now = startMillis
        val sleeps = mutableListOf<Int>()

        override fun nowMillis(): Long = now

        override fun sleepSeconds(seconds: Int) {
            sleeps.add(seconds)
            now += seconds * 1000L
        }
    }

    private class FakeDevice : PayloadDevice {
        var temperature: Int? = 50_000
        var online = true
        var stray = 0
        var rebootResult = true
        var bootCompleted = true
        var onlineWait = true
        var signals = RoundSignals()

        var reboots = 0
        var bootWaits = 0
        var onlineWaits = 0
        val rotateFlags = mutableListOf<Boolean>()

        override fun maxThermalMilliCelsius(): Int? = temperature

        override fun isOnline(): Boolean = online

        override fun killStrayPayloads(): Int = stray

        override fun runRound(
            rotate: Boolean,
            onTemperature: (Int) -> Unit,
            onLogTail: (String) -> Unit,
        ): RoundSignals {
            rotateFlags.add(rotate)
            temperature?.let(onTemperature)
            onLogTail("LANE_DONE timers=40000 create_errno=0")
            return signals
        }

        override fun rebootRound(): Boolean {
            reboots++
            return rebootResult
        }

        override fun waitForBootCompleted(): Boolean {
            bootWaits++
            return bootCompleted
        }

        override fun waitForOnline(): Boolean {
            onlineWaits++
            return onlineWait
        }
    }
}
