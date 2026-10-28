package com.ghostlock.app.shizuku;

import com.ghostlock.app.shizuku.IGhostlockCallback;
import com.ghostlock.app.shizuku.IGhostlockStatusCallback;

interface IGhostlockUserService {
    void destroy() = 16777114;
    void runExploit(int primaryCpu, int consumerCpu, boolean safeMode, boolean forceAttack, in byte[] profileBlob, @nullable String debugDir, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 2;
    // AIDL 事务号必须唯一: 本分支的 runPayload 占用 3, 上游的 runExploitAsManager 顺延到 4.
    void runPayload(boolean rotate, int budgetSeconds, int stallSeconds, int gateMilliCelsius, IGhostlockCallback callback) = 3;
    void runExploitAsManager(int primaryCpu, int consumerCpu, boolean safeMode, boolean forceAttack, in byte[] profileBlob, @nullable String debugDir, @nullable String managerPackage, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 4;
    // 载荷编排原语 (见任务 design.md D2): 这些只能在 uid=shell 侧做, app 进程无权限.
    int maxThermalMilliCelsius() = 5;
    int killStrayPayloads() = 6;
    // 返回 reboot 命令的退出码, 0 表示命令已发出; 成败由调用方用 boot_id 变化确认.
    int rebootDevice() = 7;
    // 返回 0 表示 /proc/modules 里 kernelsu 处于 Live, 其余为失败.
    int handoverKernelSU(@nullable String managerPackage, IGhostlockCallback callback) = 8;
}
