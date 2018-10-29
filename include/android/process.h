/*
 * Copyright (C) 2018 The Android Open Source Project
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

/**
 * @addtogroup Process
 * @{
 */

/**
 * @file process.h
 * @brief Tools for managing OS processes.
 *
 * Available since API level 29.
 */

#ifndef ANDROID_NATIVE_PROCESS_H
#define ANDROID_NATIVE_PROCESS_H

#ifdef __cplusplus
extern "C" {
#endif

#if __ANDROID_API__ >= 29

/*
 * ***********************************************
 * ** Keep in sync with android.os.Process.java **
 * ***********************************************
 *
 * This maps directly to the "nice" priorities we use in Android.
 * A thread priority should be chosen inverse-proportionally to
 * the amount of work the thread is expected to do. The more work
 * a thread will do, the less favorable priority it should get so that
 * it doesn't starve the system. Threads not behaving properly might
 * be "punished" by the kernel.
 * Use the levels below when appropriate. Intermediate values are
 * acceptable, preferably use the {MORE|LESS}_FAVORABLE constants below.
 */

/**
 * Thread priority definitions for use with AProcess_setThreadPriority(int, int) and
 * AProcess_getThreadPriority(int).
 */
enum {
  /**
   * Lowest available thread priority. Only for those who really, really don't want to run if
   * anything else is happening.
   */
  THREAD_PRIORITY_LOWEST         =  19,

  /**
   * Standard priority background threads. This gives your thread a slightly lower than normal
   * priority, so that it will have less chance of impacting the responsiveness of the user
   * interface.
   */
  THREAD_PRIORITY_BACKGROUND     =  10,

  /**
   * Standard priority of application threads.
   */
  THREAD_PRIORITY_NORMAL         =   0,

  /**
   * Standard priority of threads that are currently running a user interface that the user is
   * interacting with. Applications can not normally change to this priority; the system will
   * automatically adjust your application threads as the user moves through the UI.
   */
  THREAD_PRIORITY_FOREGROUND     =  -2,

  /**
   * Standard priority of system display threads, involved in updating the user interface.
   */
  THREAD_PRIORITY_DISPLAY        =  -4,

  /**
   * Standard priority of video threads. Applications can not normally change to this priority.
   */
  THREAD_PRIORITY_VIDEO          = -10,
  /**
   * Standard priority of audio threads. Applications can not normally change to this priority.
   */
  THREAD_PRIORITY_AUDIO          = -16,

  /**
   * Standard priority of the most important audio threads. Applications can not normally change
   * to this priority.
   */
  THREAD_PRIORITY_URGENT_AUDIO   = -19,

  /**
   * Highest priority. Applications can not normally change to this priority.
   */
  THREAD_PRIORITY_HIGHEST        = -20,

  /**
   * Minimum increment to make a priority more favorable.
   */
  THREAD_PRIORITY_MORE_FAVORABLE =  -1,

  /**
   * Minimum increment to make a priority less favorable.
   */
  THREAD_PRIORITY_LESS_FAVORABLE =  +1
};

/**
  * Sets the priority of a thread.
  *
  * \param tid thread id.
  * \param new priority level.
  * \return 0 for success, -errno on failure.
  *
  * Available since API level 29.
  */
int AProcess_setThreadPriority(int tid, int priority) __INTRODUCED_IN(29);

/**
  * Gets the priority of a thread.
  *
  * \param tid thread id.
  * \param pointer to a priority level.
  * \return 0 for success, -errno on failure.
  *
  * Available since API level 29.
  */
int AProcess_getThreadPriority(int tid, int* priority) __INTRODUCED_IN(29);

#endif /* __ANDROID_API__ >= 29 */

#ifdef __cplusplus
};
#endif

#endif // ANDROID_NATIVE_PROCESS_H

/** @} */
