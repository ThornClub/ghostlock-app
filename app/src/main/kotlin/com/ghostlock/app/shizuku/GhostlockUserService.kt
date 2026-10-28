package com.ghostlock.app.shizuku

import android.content.Context
import android.os.Process
import androidx.annotation.Keep
import com.ghostlock.app.data.ManagerScanner
import com.ghostlock.app.data.NativeProfileDocument
import com.ghostlock.app.data.payload.PayloadBridge
import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.TimeUnit
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
    ) = runExploitAsManager(primaryCpu, consumerCpu, safeMode, forceAttack, profileBlob, debugDir, null, callback, statusCallback)

    override fun runExploitAsManager(
        primaryCpu: Int,
        consumerCpu: Int,
        safeMode: Boolean,
        forceAttack: Boolean,
        profileBlob: ByteArray,
        debugDir: String?,
        managerPackage: String?,
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
                // Same resolution as the direct path: chosen manager first,
                // then the built-ins. Native gets the path via GHOSTLOCK_KSUD.
                val pm = context.packageManager
                val ksudPath = ManagerScanner.resolvePackages(managerPackage)
                    .asSequence()
                    .map { pkg ->
                        runCatching {
                            File(pm.getApplicationInfo(pkg, 0).nativeLibraryDir, "libksud.so")
                        }.getOrNull()?.takeIf { it.isFile }
                    }
                    .firstOrNull { it != null }
                ksudPath?.let { callback.onLog("<s> ksud resolved: ${it.absolutePath}") }
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
                        if (ksudPath != null) {
                            environment()["GHOSTLOCK_KSUD"] = ksudPath.absolutePath
                        }
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

    /** CVE-2026-64560 payload run: exactly one round per invocation.
     *
     *  Every attempt in the validated recipe started on a freshly booted
     *  kernel, because a miss leaves the sprayed slab state dirty. This method
     *  therefore never loops: it stages one payload, runs the payload's own
     *  read-only preflight, checks that the spray can fit under this process's
     *  signal ceiling, fires once and reports the outcome. The caller
     *  re-invokes after the reboot. The payload owns the kernel primitive; this
     *  method never claims a write it did not see a marker for. */
    override fun runPayload(
        rotate: Boolean,
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
                require(budgetSeconds > 0 && stallSeconds > 0) {
                    "invalid payload plan: budget=${budgetSeconds}s stall=${stallSeconds}s"
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
                callback.onLog(
                    "<p> one round: rotate=$rotate budget=${budgetSeconds}s " +
                        "stall=${stallSeconds}s",
                )
                waitForThermalGate(gateMilliCelsius, callback)
                val name = PayloadBridge.payloadFor(rotate)
                val source = File(context.applicationInfo.nativeLibraryDir, name)
                require(source.isFile) { "missing payload: ${source.absolutePath}" }
                val staged = File(workDir, name.removePrefix("lib").removeSuffix(".so"))
                source.copyTo(staged, overwrite = true)
                staged.setExecutable(true, false)
                requirePreflight(staged, workDir, callback)
                requireTimerBudget(callback)

                val log = File(workDir, "payload-rotate-$rotate.log").apply { writeText("") }
                callback.onLog("<p> firing ${staged.name}")
                val process = ProcessBuilder(staged.absolutePath, "--run")
                    .directory(workDir)
                    .redirectErrorStream(true)
                    .redirectOutput(log)
                    .start()
                payloadProcess = process
                val outcome =
                    awaitPayloadOutcome(process, log, budgetSeconds, stallSeconds, callback)
                when (outcome) {
                    PayloadBridge.Outcome.Hold -> {
                        /* The root child lives inside this payload process, so it stays. */
                        callback.onLog("<p> held a root child; it lives until the next reboot")
                        0
                    }
                    PayloadBridge.Outcome.Rejected -> {
                        callback.onLog("<p> payload rejected this device; stopping")
                        process.destroy()
                        2
                    }
                    PayloadBridge.Outcome.Stalled -> {
                        callback.onLog("<p> no hold (stalled); reboot before the next round")
                        process.destroy()
                        3
                    }
                    else -> {
                        callback.onLog("<p> no hold (exited); reboot before the next round")
                        process.destroy()
                        1
                    }
                }
            }.getOrElse { error ->
                runCatching { callback.onLog("<s> error: ${error.message}") }
                1
            }
            running.set(false)
            runCatching { callback.onComplete(exitCode) }
        }, "ghostlock-payload-runner").start()
    }

    /** Blocks until the hottest CPU zone drops to [gateMilliCelsius], at most
     *  300s. The validated recipe fires at 58C; hotter starts were aborted by
     *  thermal handling, and no round gained anything from waiting longer. */
    private fun waitForThermalGate(gateMilliCelsius: Int, callback: IGhostlockCallback) {
        if (maxThermalMilliCelsius() <= gateMilliCelsius) return
        callback.onLog("<p> temp=${maxThermalMilliCelsius()}mC gate=${gateMilliCelsius}mC, cooling")
        var waited = 0
        while (waited < 300 && maxThermalMilliCelsius() > gateMilliCelsius) {
            Thread.sleep(2000)
            waited += 2
        }
        callback.onLog("<p> temp=${maxThermalMilliCelsius()}mC after ${waited}s")
    }

    /** Runs the payload's own read-only self-check. `--preflight` reports the
     *  compiled-in profile and writes nothing to the kernel, so a device or
     *  parameter mismatch costs seconds instead of a burnt boot. */
    private fun requirePreflight(staged: File, workDir: File, callback: IGhostlockCallback) {
        val log = File(workDir, "payload-preflight.log").apply { writeText("") }
        val process = ProcessBuilder(staged.absolutePath, "--preflight")
            .directory(workDir)
            .redirectErrorStream(true)
            .redirectOutput(log)
            .start()
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroy()
            throw IllegalStateException("payload preflight timed out")
        }
        val text = runCatching { log.readText() }.getOrElse { "" }
        text.lineSequence().filter { it.isNotBlank() }.forEach { line ->
            runCatching { callback.onLog(line) }
        }
        require(text.contains(PayloadBridge.PreflightMarker)) {
            if (text.contains(PayloadBridge.RejectMarker)) {
                "payload rejected this device; no round can change that"
            } else {
                "payload preflight did not pass (exit=${process.exitValue()})"
            }
        }
    }

    /** Refuses to fire when the spray cannot reach the payload's timer goal.
     *  Read here, not in the payload: the child inherits these limits. */
    private fun requireTimerBudget(callback: IGhostlockCallback) {
        val limits = runCatching { File("/proc/self/limits").readText() }.getOrElse { "" }
        val pending = PayloadBridge.maxPendingSignals(limits)
        callback.onLog("<p> timer goal=${PayloadBridge.TimerGoal} max pending signals=$pending")
        require(PayloadBridge.timerBudgetFits(limits)) {
            "spray cannot reach ${PayloadBridge.TimerGoal} timers under the " +
                "$pending signal ceiling; every attempt would miss"
        }
    }

    /** Consumes the payload log until a terminal marker, an exit or a stall. */
    private fun awaitPayloadOutcome(
        process: java.lang.Process,
        log: File,
        budgetSeconds: Int,
        stallSeconds: Int,
        callback: IGhostlockCallback,
    ): PayloadBridge.Outcome {
        var processed = 0
        var lastSize = 0L
        var lastGrow = System.currentTimeMillis()
        val started = lastGrow
        while (true) {
            Thread.sleep(500)
            val outcome = readPayloadLines(
                log,
                processed,
                onLine = { line -> runCatching { callback.onLog(line) } },
                onProgress = { processed = it },
            )
            if (outcome != null) return outcome
            val size = runCatching { log.length() }.getOrDefault(0L)
            if (size > lastSize) {
                lastSize = size
                lastGrow = System.currentTimeMillis()
            }
            val now = System.currentTimeMillis()
            when {
                !process.isAlive -> return PayloadBridge.Outcome.Exited
                now - started >= budgetSeconds * 1000L -> return PayloadBridge.Outcome.Stalled
                now - lastGrow >= stallSeconds * 1000L -> return PayloadBridge.Outcome.Stalled
            }
        }
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
