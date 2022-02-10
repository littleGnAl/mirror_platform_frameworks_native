/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FRAMEWORK_NATIVE_CMD_DUMPPOOL_H_
#define FRAMEWORK_NATIVE_CMD_DUMPPOOL_H_

#include <future>
#include <queue>
#include <string>

#include <android-base/file.h>
#include <android-base/macros.h>

namespace android {
namespace os {
namespace dumpstate {

class DumpPoolTest;

/*
 * A thread pool with the fixed number of threads to execute multiple dump tasks
 * simultaneously for dumpstate. The dump task is a callable function.
 * Takes an example below for the usage of the DumpPool:
 *
 * void MyTask() {
 *    ...
 * }
 * ...
 * DumpPool pool();
 * auto task = pool.enqueueTaskWithFd("TaskName", &DumpFoo, std::placeholders::_1);
 * ...
 * task.get();
 *
 * DumpFoo is a callable function included a out_fd parameter. Using the
 * enqueueTaskWithFd method in DumpPool to enqueue the task to the pool. The
 * std::placeholders::_1 is a placeholder for DumpPool to pass a fd argument.
 *
 * std::futures returned by `enqueueTask*()` must all have their `get` methods
 * called, or have been destroyed before the DumpPool itself is destroyed.
 */
class DumpPool {
  friend class android::os::dumpstate::DumpPoolTest;

  public:
    /*
     * Will waits until all threads exit the loop. Destroying DumpPool before destroying the
     * associated std::futures created by `enqueueTask*` will cause an abort on Android because
     * Android is built with `-fno-exceptions`.
     */
    ~DumpPool();

    /*
     * Starts the threads in the pool.
     *
     * |thread_counts| the number of threads to start.
     */
    void start(int thread_counts = 4);

    /*
     * Adds a task into the queue of the thread pool.
     *
     * |duration_title| The name of the task. It's also the title of the
     * DurationReporter log.
     * |f| Callable function to execute the task.
     * |args| A list of arguments.
     *
     * TODO(b/164369078): remove this api to have just one enqueueTask for consistency.
     */
    template<class F, class... Args>
    std::future<void> enqueueTask(const std::string& duration_title, F&& f, Args&&... args) {
        std::function<void(void)> func = std::bind(std::forward<F>(f),
                std::forward<Args>(args)...);
        return post(duration_title, func);
    }

    /*
    // TODO(cmtm): figure out this mess
    template<class F, class... Args>
    std::future<void> BetterEnqueueTask(F&& f, Args&&... args) {
        std::promise<std::invoke_result_t<F&&, Args&&...>> promise;
        auto future = promise.get_future();

        auto func = std::bind(std::forward<F>(f), std::forward<Args>(args)...);
        EnqueueCallable(std::packaged_task<void()>([func = std::move(func), promise = std::move(promise)]()mutable { func(); promise.set_value(); }));
        return future;
    }


    template<class F, class... Args>
    std::future<std::invoke_result_t<F&&, Args&&...>> BetterEnqueueTask(F&& f, Args&&... args) {
        std::promise<std::invoke_result_t<F&&, Args&&...>> promise;
        auto future = promise.get_future();

        auto func = std::bind(std::forward<F>(f), std::forward<Args>(args)...);
        EnqueueCallable(std::packaged_task<void()>([func = std::move(func), promise = std::move(promise)]()mutable { promise.set_value(func()); }));
        return future;

    }
    */

  private:
    using Task = std::packaged_task<void()>;

    template<class T> void invokeTask(T dump_func, const std::string& duration_title);

    template<class T>
    std::future<void> post(const std::string& duration_title, T dump_func) {
        std::packaged_task<void()> packaged_task([=]() {
            invokeTask(dump_func, duration_title);
        });
        std::unique_lock lock(lock_);
        auto future = packaged_task.get_future();
        // Wrap a packaged_task into a packaged task for type erasure.
        tasks_.push(Task([pt = std::move(packaged_task)]()mutable { pt(); }));
        condition_variable_.notify_one();
        return future;
    }

    void setThreadName(const pthread_t thread, int id);
    void loop();

  private:

    /* A path to a temporary folder for threads to create temporary files. */
    bool shutdown_ = false;
    std::mutex lock_;  // A lock for the tasks_.
    std::condition_variable condition_variable_;

    std::vector<std::thread> threads_;
    std::queue<Task> tasks_;
};

}  // namespace dumpstate
}  // namespace os
}  // namespace android

#endif //FRAMEWORK_NATIVE_CMD_DUMPPOOL_H_
