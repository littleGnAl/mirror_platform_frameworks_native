package android.frameworks.adpf;

import android.frameworks.adpf.PipelineStage;

interface IAdpfService {
    long createPipeline(in PipelineStage[] concurrentStages, long stageDurationMicros);
    void attachEglContext(long pipelineId, long context);
    void attachVkCommandBuffer(long pipelineId, long commandBuffer);
    void destroyPipeline(long pipelineId);

    oneway void reportCpuCompletionTime(long pipelineId, in long[] durationPerStageMicros);
    oneway void reportGpuCompletionTime(long pipelineId, long durationMicros);

    oneway void hintLowLatency(in int[] lowLatencyTids);

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
    oneway void hintMode(int mode, long majorPhase, int minorPhase);

    void allowAppSpecificOptimizations(boolean enable);
    void permitFidelityDegradation(boolean enable);
}
