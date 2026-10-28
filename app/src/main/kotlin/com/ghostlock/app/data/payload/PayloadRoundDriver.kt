package com.ghostlock.app.data.payload

/**
 * CVE-2026-64560 载荷的轮次驱动。
 *
 * 这里只有决策, 没有任何 Android 依赖: 温度采样、载荷进程、重启与清理都由 [PayloadDevice]
 * 提供, 时间与等待由 [Clock] 提供, 因此整条编排可以在 JVM 单测里用假设备跑完。
 *
 * 语义来自工具 `root_bridge.ps1` (见任务 research/02-tool-semantics.md):
 * 单轮几乎不中, 命中依赖轮间重启换干净内核, 所以"一轮"= 一次载荷进程 + 一次结果判定,
 * 驱动负责决定下一轮什么时候、用哪个载荷、要不要先冷却或重启。
 */
class PayloadRoundDriver(
    private val plan: PayloadBridge.Plan,
    private val device: PayloadDevice,
    private val clock: Clock,
    private val onRound: (RoundRecord) -> Unit = {},
    private val onLog: (String) -> Unit = {},
) {
    /** 一轮的最终判定 (工具里对应 HOLD / MISS / CRASH / HOTABORT / REJECT)。 */
    enum class RoundResult {
        /** 载荷拿到 root child; 唯一的成功标记。 */
        Hold,

        /** 载荷退出但设备仍在线, 或载荷日志静默超时。 */
        Miss,

        /** 载荷退出且设备掉线 (内核崩了)。 */
        Crash,

        /** 轮内过热, 主动中止。 */
        HotAbort,

        /** 载荷判定这台设备不受支持; 整个 run 立即终止。 */
        Rejected,
    }

    /** 轮前冷却的放行方式 (工具 Wait-Cool 的三态)。 */
    enum class CoolGate {
        /** 采样已经降到门限以下。 */
        Exact,

        /** 平台期放行: 窗口内降幅不足且没有高出容差。 */
        PlateauBypass,

        /** 超过 coolTimeout 仍未达标。 */
        Timeout,
    }

    /** 载荷一次调用留给驱动的原始信号; 判定由 [classify] 统一做。 */
    data class RoundSignals(
        val sawHold: Boolean = false,
        val sawReject: Boolean = false,
        val stalled: Boolean = false,
        /** 轮内越过 panic 门被主动中止 (工具 HOTABORT)。 */
        val sawHotAbort: Boolean = false,
        val onlineAfterExit: Boolean = true,
    )

    /** 一轮的完整记录, 供 UI 与诊断导出使用。 */
    data class RoundRecord(
        val round: Int,
        val result: RoundResult,
        val rotate: Boolean,
        val payload: String,
        val coolGate: CoolGate,
        val startMilliCelsius: Int?,
        val peakMilliCelsius: Int?,
        val temperatureTrace: List<Int>,
        val durationMillis: Long,
        val strayLeft: Int,
        val quietSeconds: Int,
        val spray: SprayHealth?,
        /** 该轮载荷日志尾部, 诊断导出直接落盘。 */
        val logTail: String = "",
    )

    /** 整个 run 的结局。 */
    data class RunSummary(
        val records: List<RoundRecord>,
        val holdRound: Int?,
        val aborted: Boolean,
        val abortReason: String?,
    )

    /** 载荷一次调用的执行者; 生产实现把 AIDL 原语接在这里。 */
    interface PayloadDevice {
        /** CPU 相关 zone 的最高温度 (mC), 读不到返回 null。 */
        fun maxThermalMilliCelsius(): Int?

        /** Shizuku / UserService 是否在线。 */
        fun isOnline(): Boolean

        /** 清杀残留载荷进程, 返回清理后仍在的数量。 */
        fun killStrayPayloads(): Int

        /** 跑一轮载荷 (阻塞到该轮结束), 每 [plan] 的 pollSeconds 报一次温度和日志尾部。 */
        fun runRound(
            rotate: Boolean,
            onTemperature: (Int) -> Unit,
            onLogTail: (String) -> Unit,
        ): RoundSignals

        /** 主动重启并等到设备回来、SELinux 回 Enforcing、boot_id 变化。 */
        fun rebootRound(): Boolean

        /** 等 sys.boot_completed=1。 */
        fun waitForBootCompleted(): Boolean

        /** 等设备回到在线。 */
        fun waitForOnline(): Boolean
    }

    /** 时间与等待, 单测里用假时钟跳过真实 sleep。 */
    interface Clock {
        fun nowMillis(): Long
        fun sleepSeconds(seconds: Int)
    }

    fun run(): RunSummary {
        val records = mutableListOf<RoundRecord>()
        var crashStreak = 0
        var fastLeft = 0
        var holdRound: Int? = null

        for (round in 1..plan.rounds) {
            val gate = awaitCooling(plan.gateMilliCelsius, plan.coolTimeoutSeconds)
            if (gate == CoolGate.Timeout) {
                onLog("<p> cooling timed out before round $round; stopping")
                return RunSummary(records, holdRound, aborted = true, abortReason = "cool-timeout")
            }
            if (!device.isOnline()) {
                onLog("<p> device offline before round $round; waiting")
                if (!device.waitForOnline()) {
                    onLog("<p> device did not come back; stopping")
                    return RunSummary(records, holdRound, aborted = true, abortReason = "offline")
                }
            }

            val strayLeft = device.killStrayPayloads()
            if (strayLeft > 0) onLog("<p> round $round: $strayLeft stray payload(s) survived the sweep")

            /* 奇数轮 fanout, 偶数轮 rotate: 两种定时器策略逐轮交替, 与工具一致。 */
            val rotate = round % 2 == 0
            val quiet = if (fastLeft > 0) {
                fastLeft--
                plan.fastQuietSeconds
            } else {
                plan.quietSeconds
            }
            if (quiet > 0) clock.sleepSeconds(quiet)

            val startedAt = clock.nowMillis()
            val startTemp = device.maxThermalMilliCelsius()
            val trace = mutableListOf<Int>()
            startTemp?.let { trace.add(it) }
            var peak = startTemp ?: Int.MIN_VALUE
            var tail = ""

            onLog("<p> round $round/${plan.rounds} payload=${PayloadBridge.payloadFor(rotate)}")
            val signals = device.runRound(
                rotate = rotate,
                onTemperature = { celsius ->
                    trace.add(celsius)
                    if (celsius > peak) peak = celsius
                },
                onLogTail = { tail = it },
            )
            val result = classify(signals)
            val record = RoundRecord(
                round = round,
                result = result,
                rotate = rotate,
                payload = PayloadBridge.payloadFor(rotate),
                coolGate = gate,
                startMilliCelsius = startTemp,
                peakMilliCelsius = peak.takeIf { it != Int.MIN_VALUE },
                temperatureTrace = trace.toList(),
                durationMillis = clock.nowMillis() - startedAt,
                strayLeft = strayLeft,
                quietSeconds = quiet,
                spray = sprayHealth(tail),
                logTail = tail,
            )
            records.add(record)
            onRound(record)

            if (result == RoundResult.Hold) {
                holdRound = round
                return RunSummary(records, holdRound, aborted = false, abortReason = null)
            }
            if (result == RoundResult.Rejected) {
                onLog("<p> payload rejected this device; no round can change that")
                return RunSummary(records, holdRound, aborted = true, abortReason = "rejected")
            }

            crashStreak = if (result == RoundResult.Crash) crashStreak + 1 else 0
            if (crashStreak >= plan.crashStreakForFullReset) {
                /* 连续崩说明喷堆把 slab 弄脏了: 等系统起完再降到重置温度, 并取消快速间隔。 */
                onLog("<p> $crashStreak consecutive crash(es); full reset before the next round")
                if (!device.waitForBootCompleted()) {
                    onLog("<p> boot did not complete; stopping")
                    return RunSummary(records, holdRound, aborted = true, abortReason = "boot-stuck")
                }
                awaitCooling(plan.rebootCoolMilliCelsius, plan.coolTimeoutSeconds)
                fastLeft = 0
            } else if (result == RoundResult.Crash) {
                onLog("<p> kernel crashed on round $round; waiting for the device")
                if (!device.waitForOnline()) {
                    onLog("<p> device did not come back; stopping")
                    return RunSummary(records, holdRound, aborted = true, abortReason = "offline")
                }
                fastLeft = plan.fastAfterCrash
            } else if (plan.rebootEachRound && round < plan.rounds) {
                /* MISS 留下的是脏 slab 状态, 换一个干净的 boot 比原地重试更有价值。 */
                if (device.rebootRound()) {
                    fastLeft = 1
                } else {
                    onLog("<p> clean reboot failed; continuing on the current boot")
                }
            }
        }

        return RunSummary(records, holdRound, aborted = false, abortReason = null)
    }

    /** 纯判定: 载荷信号 -> 本轮结果。 */
    fun classify(signals: RoundSignals): RoundResult = when {
        signals.sawHold -> RoundResult.Hold
        signals.sawReject -> RoundResult.Rejected
        signals.sawHotAbort -> RoundResult.HotAbort
        signals.stalled -> RoundResult.Miss
        !signals.onlineAfterExit -> RoundResult.Crash
        else -> RoundResult.Miss
    }

    /**
     * 轮前冷却。冷到门限以下直接放行; 否则等热平衡: 最近一个平台期内降幅不足
     * [PayloadBridge.Plan.plateauDeltaMilliCelsius] 且温度没有高出容差时放行; 超时返回 Timeout。
     */
    fun awaitCooling(limitMilliCelsius: Int, timeoutSeconds: Int): CoolGate {
        val deadline = clock.nowMillis() + timeoutSeconds * 1000L
        var windowStart = clock.nowMillis()
        var windowBest = Int.MAX_VALUE
        var bestSeen = Int.MAX_VALUE
        while (true) {
            val sample = device.maxThermalMilliCelsius()
            if (sample == null) return CoolGate.Exact
            if (sample <= limitMilliCelsius) return CoolGate.Exact
            if (sample < bestSeen) bestSeen = sample
            if (sample < windowBest) windowBest = sample

            if (clock.nowMillis() >= deadline) return CoolGate.Timeout

            val windowElapsed = clock.nowMillis() - windowStart
            if (windowElapsed >= plan.plateauWindowSeconds * 1000L) {
                val improved = bestSeen - windowBest >= plan.plateauDeltaMilliCelsius
                val withinMargin = sample <= limitMilliCelsius + plan.plateauMarginMilliCelsius
                if (!improved && withinMargin) return CoolGate.PlateauBypass
                windowStart = clock.nowMillis()
                windowBest = sample
            }
            clock.sleepSeconds(plan.pollSeconds)
        }
    }

    /** 喷堆健康度: 载荷日志里的 timer 目标与实际创建数。 */
    data class SprayHealth(
        val timerGoal: Int,
        val timers: Int,
        val createErrno: Int,
    ) {
        val short: Boolean get() = timerGoal > 0 && timers < timerGoal
        val hitSignalCeiling: Boolean get() = short && createErrno == 11
    }

    companion object {
        private val TimerGoalPattern = Regex("timer_goal=(\\d+)")
        private val LaneDonePattern = Regex("LANE_DONE[^\\n]*")
        private val TimersPattern = Regex("timers=(\\d+)")
        private val CreateErrnoPattern = Regex("create_errno=(\\d+)")

        /** 从载荷日志尾部解析喷堆健康度; 缺字段时按 0 处理, 由 [SprayHealth.short] 判定告警。 */
        fun sprayHealth(logTail: String): SprayHealth? {
            if (logTail.isBlank()) return null
            val goal = TimerGoalPattern.find(logTail)?.groupValues?.get(1)?.toIntOrNull() ?: 0
            val lane = LaneDonePattern.findAll(logTail).lastOrNull()?.value ?: return null
            val timers = TimersPattern.find(lane)?.groupValues?.get(1)?.toIntOrNull() ?: return null
            val errno = CreateErrnoPattern.find(lane)?.groupValues?.get(1)?.toIntOrNull() ?: 0
            return SprayHealth(timerGoal = goal, timers = timers, createErrno = errno)
        }
    }
}
