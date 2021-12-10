/*
 * Copyright (C) 2022 The Android Open Source Project
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

// On some versions of clang, RpcServer.cpp refuses to link without accept4
__attribute__((weak)) extern "C" int accept4(int, void*, void*, int) {
    return 0;
}

// Placeholder for poll used by FdTrigger
__attribute__((weak)) extern "C" int poll(void*, long, int) {
    return 0;
}
