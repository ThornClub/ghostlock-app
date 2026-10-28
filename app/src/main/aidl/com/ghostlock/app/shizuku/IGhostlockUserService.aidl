package com.ghostlock.app.shizuku;

import com.ghostlock.app.shizuku.IGhostlockCallback;
import com.ghostlock.app.shizuku.IGhostlockStatusCallback;

interface IGhostlockUserService {
    void destroy() = 16777114;
    void runExploit(int primaryCpu, int consumerCpu, boolean safeMode, boolean forceAttack, in byte[] profileBlob, @nullable String debugDir, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 2;
    // AIDL 事务号必须唯一: 本分支的 runPayload 占用 3, 上游的 runExploitAsManager 顺延到 4.
    void runPayload(int rounds, int budgetSeconds, int stallSeconds, int gateMilliCelsius, IGhostlockCallback callback) = 3;
    void runExploitAsManager(int primaryCpu, int consumerCpu, boolean safeMode, boolean forceAttack, in byte[] profileBlob, @nullable String debugDir, @nullable String managerPackage, IGhostlockCallback callback, IGhostlockStatusCallback statusCallback) = 4;
}
