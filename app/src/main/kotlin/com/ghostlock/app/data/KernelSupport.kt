package com.ghostlock.app.data

import com.ghostlock.app.data.payload.PayloadBridge

/**
 * 内核支持判定。三条来源: 内置 profile 登记、用户导入的 offsets、载荷服务内核。
 * 判据只在这里组合, 载荷内核的标记匹配仍由 [PayloadBridge] 独占。
 */
internal object KernelSupport {
    fun isSupported(
        release: String,
        builtinUnames: Set<String>,
        hasImportedOffsets: Boolean,
    ): Boolean = release in builtinUnames || hasImportedOffsets || PayloadBridge.isFindN5Kernel(release)
}
