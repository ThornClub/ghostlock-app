package com.ghostlock.app.data.payload

import android.content.SharedPreferences

/**
 * 载荷 run 的会话存档。
 *
 * 为什么需要: 驱动跑在手机上, 而这条 recipe 的每一步都要"换一个干净的 boot"(MISS 后主动重启,
 * CRASH 后设备自己重启)。重启会把 app 一起带走, 所以轮次进度必须落在盘上, 下次启动接着跑。
 * 工具是在 Windows 端编排的, 天然躲过了这个问题; GhostLock 只能自己记住进度。
 */
internal class PayloadRunSessionStore(private val preferences: SharedPreferences) {
    data class Session(val nextRound: Int, val totalRounds: Int)

    /** 未完成的 run; null 表示没有正在进行的会话。 */
    fun load(): Session? {
        if (!preferences.getBoolean(KeyActive, false)) return null
        val next = preferences.getInt(KeyNextRound, 1)
        val total = preferences.getInt(KeyTotalRounds, 0)
        if (next <= 0) return null
        return Session(nextRound = next, totalRounds = total)
    }

    fun start(totalRounds: Int) {
        preferences.edit()
            .putBoolean(KeyActive, true)
            .putInt(KeyTotalRounds, totalRounds)
            .putInt(KeyNextRound, 1)
            .apply()
    }

    /** 记录"下一轮该跑第几轮"; 每轮开始前写, 崩在这一轮时下次会重跑同一轮。 */
    fun advance(nextRound: Int) {
        preferences.edit().putInt(KeyNextRound, nextRound).apply()
    }

    fun finish() {
        /* 只清本会话的键: clear() 会把整个 app 的设置一起清掉。 */
        preferences.edit()
            .remove(KeyActive)
            .remove(KeyNextRound)
            .remove(KeyTotalRounds)
            .apply()
    }

    private companion object {
        const val KeyActive = "payload_run_active"
        const val KeyNextRound = "payload_run_next_round"
        const val KeyTotalRounds = "payload_run_total_rounds"
    }
}
