package com.ghostlock.app.shizuku

import android.content.Context
import android.os.Process
import androidx.annotation.Keep
import com.ghostlock.app.data.NativeProfileDocument
import com.ghostlock.app.data.payload.PayloadBridge
import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean

@Keep
class GhostlockUserService(private val context: Context) : IGhostlockUserService.Stub() {
    private val running = AtomicBoolean(false)
    /** Live 64560 payload process; a hold keeps this child alive until reboot. */
    @Volatile
    private var payloadProcess: java.lang.Process? = null

    private companion object {
        const val StatusMarker = "\u001eGLK_STATUS"
        const val StatusAck = "\u001eGLK_STATUS_ACK\n"
        const val StatusDisabled = "\u001eGLK_STATUS_DISABLED"
    }

    override fun runExploit(
        primaryCpu: Int,
        consumerCpu: Int,
        safeMode: Boolean,
        forceAttack: Boolean,
        profileBlob: ByteArray,
        debugDir: String?,
        callback: IGhostlockCallback,
        statusCallback: IGhostlockStatusCallback,
    ) {
        if (!running.compareAndSet(false, true)) {
            callback.onLog("<s> error: another GhostLock process is already running")
            callback.onComplete(1)
            return
        }
        Thread({
            val exitCode = runCatching {
                require(Process.myUid() == Process.SHELL_UID) {
                    "Shizuku UserService uid=${Process.myUid()}, expected ${Process.SHELL_UID}"
                }
                val status = File("/proc/self/status").readText()
                require(Regex("(?m)^Seccomp:\\s*0$").containsMatchIn(status)) {
                    "Shizuku UserService is still seccomp-filtered"
                }
                val release = System.getProperty("os.version", "").orEmpty()
                require(profileBlob.size >= 16) { "profile blob is too short" }
                // PROFILE-SUGGEST-01: recommend_shizuku is a suggestion; the
                // blob's meta section carries it, and the app already chose the
                // Shizuku path, so it is logged, never a gate.
                if (NativeProfileDocument.fromBinary(profileBlob)?.recommendShizuku != 1u) {
                    callback.onLog("<s> kernel does not require Shizuku; running on user request")
                }

                val binary = File(context.applicationInfo.nativeLibraryDir, "libghostlock.so")
                require(binary.isFile) { "missing GhostLock binary: ${binary.absolutePath}" }

                val workDir = File("/data/local/tmp/ghostlock-app").apply {
                    require(isDirectory || mkdirs()) { "cannot create $absolutePath" }
                }
                callback.onLog("<s> Shizuku ready: uid=${Process.myUid()} Seccomp=0")
                callback.onLog("<s> kernel: $release")
                val nativeLog = File(workDir, ".ghostlock_native.log")
                // U01-S14: per-run KernelSU log so a previous run's markers can
                // never satisfy the handoff probe; the native process receives
                // the resolved path via GHOSTLOCK_KSU_LOG.
                val ksuLog = File(workDir, "ghostlock-ksu-${System.currentTimeMillis()}.log")
                // v2: safe_mode lives in the meta section; there is no fixed
                // slot offset, so the blob is rescanned and rewritten.
                val effectiveBlob = if (safeMode) {
                    NativeProfileDocument.patchSafeMode(profileBlob) ?: profileBlob
                } else {
                    profileBlob
                }
                val argv = mutableListOf(
                    binary.absolutePath,
                    "--ghostlock-app-call",
                    "--enable-status-record",
                )
                if (forceAttack) {
                    argv += "--force-attack"
                }
                if (!debugDir.isNullOrEmpty()) {
                    argv += listOf("--dump-kernel-log", debugDir)
                }
                callback.onLog("<b> starting native: ${binary.absolutePath}")
                ProcessBuilder(argv)
                    .directory(workDir)
                    .redirectErrorStream(true)
                    .redirectOutput(nativeLog)
                    .apply {
                        environment()["GHOSTLOCK_HOME"] = workDir.absolutePath
                        environment()["TMPDIR"] = workDir.absolutePath
                        environment()["HOME"] = workDir.absolutePath
                        environment()["GHOSTLOCK_KSU_LOG"] = ksuLog.absolutePath
                    }
                    .start()
                    .let { process ->
                        val stdinOut = process.outputStream
                        /* Length-prefixed GLK1; stdin stays open for the ACK. */
                        runCatching {
                            val length = effectiveBlob.size
                            stdinOut.write(
                                byteArrayOf(
                                    (length ushr 24).toByte(),
                                    (length ushr 16).toByte(),
                                    (length ushr 8).toByte(),
                                    length.toByte(),
                                ),
                            )
                            stdinOut.write(effectiveBlob)
                            stdinOut.flush()
                        }
                        // The native process writes its log to a file and this
                        // tailer forwards lines asynchronously. Reading a pipe
                        // here applied backpressure inside the PI race window
                        // (every line also costs a binder round trip), which
                        // stalled the route and ended in a kernel panic.
                        val tailer = Thread({
                            relayLog(nativeLog, callback, statusCallback, stdinOut)
                        }, "ghostlock-shizuku-tailer").apply {
                            isDaemon = true
                            start()
                        }
                        val exitCode = process.waitFor()
                        callback.onLog("<b> native exited code=$exitCode")
                        Thread.sleep(200)
                        tailer.interrupt()
                        tailer.join(1000)
                        exitCode
                    }
            }.getOrElse { error ->
                runCatching { callback.onLog("<s> error: ${error.message}") }
                1
            }
            running.set(false)
            runCatching { callback.onComplete(exitCode) }
        }, "ghostlock-shizuku-runner").start()
    }

    /** CVE-2026-64560 payload run, batch 1: staging, round loop and marker
     *  reporting only. The payload owns the kernel primitive; this method never
     *  claims a write it did not see a marker for. */
    override fun runPayload(
        rounds: Int,
        budgetSeconds: Int,
        stallSeconds: Int,
        gateMilliCelsius: Int,
        callback: IGhostlockCallback,
    ) {
        if (!running.compareAndSet(false, true)) {
            callback.onLog("<s> error: another GhostLock process is already running")
            callback.onComplete(1)
            return
        }
        Thread({
            val exitCode = runCatching {
                require(Process.myUid() == Process.SHELL_UID) {
                    "Shizuku UserService uid=${Process.myUid()}, expected ${Process.SHELL_UID}"
                }
                require(rounds > 0 && budgetSeconds > 0 && stallSeconds > 0) {
                    "invalid payload plan: rounds=$rounds budget=${budgetSeconds}s stall=${stallSeconds}s"
                }
                val release = System.getProperty("os.version", "").orEmpty()
                callback.onLog("<s> kernel: $release")
                require(PayloadBridge.isFindN5Kernel(release)) {
                    "payload bridge is validated for the " +
                        "${PayloadBridge.FindN5KernelMarker} build only"
                }
                val workDir = File("/data/local/tmp/ghostlock-app").apply {
                    require(isDirectory || mkdirs()) { "cannot create $absolutePath" }
                }
                callback.onLog("<p> rounds=$rounds budget=${budgetSeconds}s stall=${stallSeconds}s")
                var code = 1
                var round = 1
                while (round <= rounds) {
                    val thermal = maxThermalMilliCelsius()
                    if (thermal > 0) {
                        callback.onLog("<p> temp=${thermal}mC gate=${gateMilliCelsius}mC")
                        var cooled = 0
                        while (cooled < 120 && maxThermalMilliCelsius() > gateMilliCelsius) {
                            Thread.sleep(2000)
                            cooled += 2
                        }
                    }
                    val name = PayloadBridge.payloadForRound(round)
                    val source = File(context.applicationInfo.nativeLibraryDir, name)
                    require(source.isFile) { "missing payload: ${source.absolutePath}" }
                    val staged = File(workDir, name.removePrefix("lib").removeSuffix(".so"))
                    source.copyTo(staged, overwrite = true)
                    staged.setExecutable(true, false)
                    val log = File(workDir, "payload-round-$round.log").apply { writeText("") }
                    callback.onLog("<p> round $round/$rounds payload=${staged.name}")
                    val process = ProcessBuilder(staged.absolutePath, "--run")
                        .directory(workDir)
                        .redirectErrorStream(true)
                        .redirectOutput(log)
                        .start()
                    payloadProcess = process
                    var processed = 0
                    var lastSize = 0L
                    var lastGrow = System.currentTimeMillis()
                    val started = lastGrow
                    var outcome: PayloadBridge.Outcome? = null
                    /* Poll the log file rather than a pipe: reading a pipe here
                     * applies backpressure inside the payload's race window. */
                    while (outcome == null) {
                        Thread.sleep(500)
                        outcome = readPayloadLines(
                            log,
                            processed,
                            onLine = { line -> runCatching { callback.onLog(line) } },
                            onProgress = { processed = it },
                        )
                        if (outcome != null) break
                        val size = runCatching { log.length() }.getOrDefault(0L)
                        if (size > lastSize) {
                            lastSize = size
                            lastGrow = System.currentTimeMillis()
                        }
                        val now = System.currentTimeMillis()
                        when {
                            !process.isAlive -> {
                                outcome = PayloadBridge.Outcome.Exited
                                break
                            }
                            now - started >= budgetSeconds * 1000L -> {
                                outcome = PayloadBridge.Outcome.Stalled
                                break
                            }
                            now - lastGrow >= stallSeconds * 1000L -> {
                                outcome = PayloadBridge.Outcome.Stalled
                                break
                            }
                        }
                    }
                    when (outcome) {
                        PayloadBridge.Outcome.Hold -> {
                            callback.onLog("<p> round $round held a root child; it stays " +
                                "alive until the next reboot")
                            code = 0
                            break
                        }
                        PayloadBridge.Outcome.Rejected -> {
                            callback.onLog("<p> payload rejected this device; stopping")
                            code = 2
                            process.destroy()
                            break
                        }
                        else -> {
                            callback.onLog("<p> round $round result=${outcome} (no root)")
                            process.destroy()
                            round++
                        }
                    }
                }
                code
            }.getOrElse { error ->
                runCatching { callback.onLog("<s> error: ${error.message}") }
                1
            }
            running.set(false)
            runCatching { callback.onComplete(exitCode) }
        }, "ghostlock-payload-runner").start()
    }

    /** Hottest CPU/SoC thermal zone in milli-Celsius, or 0 when unreadable. */
    private fun maxThermalMilliCelsius(): Int {
        var best = 0
        val root = File("/sys/class/thermal")
        val zones = root.listFiles() ?: return 0
        for (zone in zones) {
            val type = runCatching { File(zone, "type").readText().trim() }.getOrNull() ?: continue
            if (!(type.startsWith("cpu-") || type.startsWith("cpuss-") ||
                    type.startsWith("soc_therm"))
            ) {
                continue
            }
            val value = runCatching { File(zone, "temp").readText().trim().toInt() }.getOrNull()
                ?: continue
            if (value > best) best = value
        }
        return best
    }

    /** Consume complete payload log lines from [processed]; returns the first
     *  terminal outcome, reports every line through [onLine], and updates
     *  [onProgress] with the new offset. */
    private fun readPayloadLines(
        log: File,
        processed: Int,
        onLine: (String) -> Unit,
        onProgress: (Int) -> Unit,
    ): PayloadBridge.Outcome? {
        val text = runCatching { log.readText() }.getOrNull() ?: return null
        val end = text.lastIndexOf('\n')
        if (end < processed) return null
        for (line in text.substring(processed, end + 1).lineSequence()) {
            if (line.isEmpty()) continue
            runCatching { onLine(line) }
            val outcome = PayloadBridge.classify(line)
            if (outcome != null) {
                onProgress(end + 1)
                return outcome
            }
        }
        onProgress(end + 1)
        return null
    }
    /** Forward complete native log lines without ever blocking the native
     * process; the file is the transport, binder is only the display path. */
    /** Forwards status events to the app (persist) and ACKs the native process;
     *  returns true when the line was a status event. */
    private fun handleStatusLine(
        line: String,
        statusCallback: IGhostlockStatusCallback,
        stdinOut: java.io.OutputStream,
    ): Boolean {
        if (!line.startsWith(StatusMarker)) return false
        if (line.contains(StatusDisabled)) {
            runCatching { statusCallback.onStatus("", "disabled") }
            return true
        }
        val parts = line.removePrefix(StatusMarker).trim().split(' ')
        if (parts.size >= 2) {
            runCatching { statusCallback.onStatus(parts[0], parts[1]) }
            runCatching {
                stdinOut.write(StatusAck.toByteArray(Charsets.UTF_8))
                stdinOut.flush()
            }
        }
        return true
    }

    private fun relayLog(
        logFile: File,
        callback: IGhostlockCallback,
        statusCallback: IGhostlockStatusCallback,
        stdinOut: java.io.OutputStream,
    ) {
        var offset = 0L
        val pending = StringBuilder()
        while (!Thread.currentThread().isInterrupted) {
            try {
                if (logFile.isFile) {
                    RandomAccessFile(logFile, "r").use { handle ->
                        if (offset > handle.length()) {
                            offset = 0
                            pending.clear()
                        }
                        handle.seek(offset)
                        while (true) {
                            val byte = handle.read()
                            if (byte == -1) break
                            if (byte == '\n'.code) {
                                val line = pending.toString()
                                pending.clear()
                                offset = handle.filePointer
                                if (line.isNotEmpty()) {
                                    if (!handleStatusLine(line, statusCallback, stdinOut)) {
                                        runCatching { callback.onLog(line) }
                                    }
                                }
                            } else {
                                pending.append(byte.toChar())
                            }
                        }
                    }
                }
                Thread.sleep(100)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            } catch (_: Exception) {
                try {
                    Thread.sleep(200)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return
                }
            }
        }
    }

    override fun destroy() {
        payloadProcess?.destroy()
        if (!running.get()) kotlin.system.exitProcess(0)
    }
}
