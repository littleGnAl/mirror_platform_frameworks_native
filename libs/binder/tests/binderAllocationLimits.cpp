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

#include <malloc.h>

#include <android-base/logging.h>
#include <gtest/gtest.h>

static const auto orig_malloc_hook = __malloc_hook;
static const auto orig_realloc_hook = __realloc_hook;

// FIXME: want nested 'with ... hook' functions

void install_orig_hooks() {
    __malloc_hook = orig_malloc_hook;
    __realloc_hook = orig_realloc_hook;
}

void* abort_malloc_hook(size_t bytes, const void* arg) {
  install_orig_hooks();
  std::cout << "malloc! bytes: " << bytes << " arg: " << arg <<  std::endl;
  _exit(1);
  return orig_malloc_hook(bytes, arg);
}

void* abort_realloc_hook(void* ptr, size_t bytes, const void* arg) {
  install_orig_hooks();
  // FIXME more logs
  std::cout << "realloc! bytes:" << bytes << std::endl;
  _exit(1);
  return orig_realloc_hook(ptr, bytes, arg);
}

void install_abort_hooks() {
    __malloc_hook = abort_malloc_hook;
    __realloc_hook = abort_realloc_hook;
}

void trigger_malloc() {
    std::cout << "I am going to be triggering a malloc, for sure!" << std::endl;
}

int main(int argc, char** argv) {
    CHECK(argc == 1) << argc;
    if (getenv("LIBC_HOOKS_ENABLE") == nullptr) {
        CHECK(0 == setenv("LIBC_HOOKS_ENABLE", "1", true /*overwrite*/));
        execl(argv[0], argv[0], nullptr);
    }
    install_abort_hooks();
    trigger_malloc();
    return 0;
}
