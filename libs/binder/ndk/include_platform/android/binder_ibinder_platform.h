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

#pragma once

#ifdef __ANDROID_APEX__
#error this is only for platform code
#endif

#include <android/binder_ibinder.h>
#include <binder/IBinder.h>

android::sp<android::IBinder> AIBinder_toPlatformBinder(AIBinder* binder);
AIBinder* PlatformBinder_toAIBinder(const android::sp<android::IBinder>& binder);
