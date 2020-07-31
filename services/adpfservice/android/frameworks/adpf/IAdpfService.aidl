package android.frameworks.adpf;

interface IAdpfService {
    long createStage(in int[] threadIds, long desiredDurationMicros);
    void attachEglContext(long stageId, long context);
    void attachVkCommandBuffer(long stageId, long commandBuffer);
    void destroyStage(long stageId);

    oneway void reportCpuCompletionTime(long stageId, long actualDurationMicros);
    oneway void reportGpuCompletionTime(long stageId, long actualDurationMicros);

    oneway void hintLowLatency(in int[] threadIds);

    const int UNIT_CPU = 1;
    const int UNIT_GPU = 2;
    const int DIRECTION_LOWER = 1;
    const int DIRECTION_HIGHER = 2;
    const int DIRECTION_MUCH_HIGHER = 3;
    oneway void hintLoadChange(int unit, int direction);

    const int MODE_UNSPECIFIED = 0;
    const int MODE_LOADING = 1;
    const int MODE_RUNNING = 2;
    const int MODE_PAUSED = 3;
    oneway void hintMode(int mode, long majorPhase, long minorPhase);

    void allowAppSpecificOptimizations(boolean enable);
    void allowFidelityDegradation(boolean enable);
}
