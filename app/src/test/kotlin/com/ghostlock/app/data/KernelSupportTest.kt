package com.ghostlock.app.data

import com.ghostlock.app.data.payload.PayloadBridge
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 内核支持判定的边界: 载荷服务内核进、index.conf 里的 release 保持进、未知 release 继续拒。
 */
class KernelSupportTest {
    private val findN5 = "6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k"
    private val builtinRelease = "5.15.41-android13-8-g8dc4c75ab7d8-ab1673212412"
    private val unknownRelease = "6.6.50-android16-8-g0123456789ab-ab99999999-4k"

    @Test
    fun `payload served kernel is supported without a builtin profile`() {
        assertTrue(PayloadBridge.isFindN5Kernel(findN5))
        assertTrue(KernelSupport.isSupported(findN5, emptySet(), hasImportedOffsets = false))
    }

    @Test
    fun `builtin release stays supported`() {
        assertTrue(
            KernelSupport.isSupported(builtinRelease, setOf(builtinRelease), hasImportedOffsets = false),
        )
    }

    @Test
    fun `imported offsets still make a release supported`() {
        assertTrue(KernelSupport.isSupported(unknownRelease, emptySet(), hasImportedOffsets = true))
    }

    @Test
    fun `unknown release without offsets stays unsupported`() {
        assertFalse(PayloadBridge.isFindN5Kernel(unknownRelease))
        assertFalse(KernelSupport.isSupported(unknownRelease, emptySet(), hasImportedOffsets = false))
    }
}
