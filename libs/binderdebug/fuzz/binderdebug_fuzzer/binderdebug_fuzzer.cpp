/******************************************************************************
 *
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 */
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <string>
#include <fstream>

#include <binder/Binder.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <binder/IPCThreadState.h>
#include <binderdebug/BinderDebug.h>
#include <semaphore.h>
#include <thread>

using namespace android;

const BinderDebugContext BinderDebugContexts[] = {
	BinderDebugContext::BINDER,
	BinderDebugContext::HWBINDER,
	BinderDebugContext::VNDBINDER,
};


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

	FuzzedDataProvider fdp(data, size);
	BinderDebugContext binderDebugContext = fdp.PickValueInArray(BinderDebugContexts);
	pid_t pid = fdp.ConsumeIntegral<pid_t>();
	BinderPidInfo pidInfo;
	std::vector<pid_t> pids;
	pid_t servicePid = fdp.ConsumeIntegral<pid_t>();
	auto handle = fdp.ConsumeIntegral<int32_t>();

	getBinderPidInfo(binderDebugContext, pid, &pidInfo);
	getBinderClientPids(binderDebugContext, pid, servicePid, handle, &pids);

	return 0;
}

