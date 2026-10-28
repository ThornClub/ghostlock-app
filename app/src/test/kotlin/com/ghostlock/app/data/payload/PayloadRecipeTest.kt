package com.ghostlock.app.data.payload

import com.ghostlock.app.data.payload.PayloadRoundDriver.Clock
import com.ghostlock.app.data.payload.PayloadRoundDriver.PayloadDevice
import com.ghostlock.app.data.payload.PayloadRoundDriver.RoundResult
import com.ghostlock.app.data.payload.PayloadRoundDriver.RoundSignals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 用真机 diag 的轮次序列回放整条编排。
 *
 * 证据来源: 2026-10-28 PKH110 (`6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k`) 的工具运行,
 * 25 轮预算内第 5 轮命中: 1 CRASH / 2 MISS / 3 CRASH / 4 CRASH / 5 HOLD
 * (`.trellis/tasks/10-28-n5-payload-kernel-support/research/02-tool-semantics.md`)。
 * 这个测试锁定的是"同一条配方在 GhostLock 的驱动上会做出同样的调度决定"。
 */
class PayloadRecipeTest {
    private val clock = FakeClock()

    @Test
    fun `the validated five-round recipe holds on round five`() {
        val device = ScriptedDevice(
            script = listOf(
                RoundSignals(onlineAfterExit = false),  // 1: CRASH
                RoundSignals(),                          // 2: MISS
                RoundSignals(onlineAfterExit = false),  // 3: CRASH
                RoundSignals(onlineAfterExit = false),  // 4: CRASH
                RoundSignals(sawHold = true),            // 5: HOLD
            ),
        )
        val plan = PayloadBridge.Plan()
        val records = mutableListOf<PayloadRoundDriver.RoundRecord>()

        val summary = PayloadRoundDriver(plan, device, clock, onRound = { records.add(it) }).run()

        assertEquals(
            listOf(
                RoundResult.Crash,
                RoundResult.Miss,
                RoundResult.Crash,
                RoundResult.Crash,
                RoundResult.Hold,
            ),
            records.map { it.result },
        )
        assertEquals(5, summary.holdRound)
        assertEquals(
            listOf(false, true, false, true, false),
            records.map { it.rotate },
        )
        /* 第 2 轮 MISS 后换干净 boot; 第 1、3 轮崩后只等设备回来; 第 4 轮把 streak 顶到 2, 走全量重置。 */
        assertEquals(1, device.reboots)
        assertEquals(2, device.onlineWaits)
        assertEquals(1, device.bootWaits)
        assertEquals("the 5th round is the last one", 5, summary.records.size)
    }

    @Test
    fun `the hold round carries the payload spray health`() {
        /* 真机命中轮的日志尾部 (节选): 40000 个 timer 全部到位。 */
        val holdTail = """
            RACE_CONFIG batch=1 max_attempts=32 timer_goal=40000 exec_repeats=4
            LANE_DONE sequence=7 timing_slot=7 victim=18102 timers=40000 deleted=40000 errors=0 create_errno=0
            BOOTID_WRITE_PASS attempt=7 q0=0xffffff802a249460 slide=0x25bb800000
            ROOT_CHILD_HOLD_PASS child=31073 uid=0 context=shell selinux_permissive=1
        """.trimIndent()
        val device = ScriptedDevice(
            script = listOf(RoundSignals(sawHold = true)),
            tail = holdTail,
        )

        val records = mutableListOf<PayloadRoundDriver.RoundRecord>()
        PayloadRoundDriver(PayloadBridge.Plan(), device, clock, onRound = { records.add(it) }).run()

        val health = records.single().spray!!
        assertEquals(40_000, health.timerGoal)
        assertEquals(40_000, health.timers)
        assertTrue("full spray", !health.short)
        assertEquals(holdTail, records.single().logTail)
    }

    @Test
    fun `a hot round is aborted instead of burning the budget`() {
        val device = ScriptedDevice(script = listOf(RoundSignals(sawHotAbort = true)))
        val records = mutableListOf<PayloadRoundDriver.RoundRecord>()

        PayloadRoundDriver(
            PayloadBridge.Plan(rounds = 1, rebootEachRound = false),
            device,
            clock,
            onRound = { records.add(it) },
        ).run()

        assertEquals(RoundResult.HotAbort, records.single().result)
    }

    @Test
    fun `a rejected device stops the run on the first round`() {
        val device = ScriptedDevice(script = listOf(RoundSignals(sawReject = true)))
        val summary = PayloadRoundDriver(PayloadBridge.Plan(), device, clock).run()

        assertTrue(summary.aborted)
        assertEquals("rejected", summary.abortReason)
        assertNull(summary.holdRound)
        assertEquals(0, device.reboots)
    }

    private class FakeClock : Clock {
        private var now = 0L
        override fun nowMillis(): Long = now
        override fun sleepSeconds(seconds: Int) {
            now += seconds * 1000L
        }
    }

    private class ScriptedDevice(
        private val script: List<RoundSignals>,
        private val tail: String = "LANE_DONE timers=40000 create_errno=0",
    ) : PayloadDevice {
        private var index = 0
        var reboots = 0
        var bootWaits = 0
        var onlineWaits = 0

        override fun maxThermalMilliCelsius(): Int? = 55_000

        override fun isOnline(): Boolean = true

        override fun killStrayPayloads(): Int = 0

        override fun runRound(
            rotate: Boolean,
            onTemperature: (Int) -> Unit,
            onLogTail: (String) -> Unit,
        ): RoundSignals {
            onTemperature(55_000)
            onLogTail(tail)
            val signals = script.getOrElse(index) { RoundSignals() }
            index++
            return signals
        }

        override fun rebootRound(): Boolean {
            reboots++
            return true
        }

        override fun waitForBootCompleted(): Boolean {
            bootWaits++
            return true
        }

        override fun waitForOnline(): Boolean {
            onlineWaits++
            return true
        }
    }
}
