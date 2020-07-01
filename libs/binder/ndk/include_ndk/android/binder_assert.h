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

#include <assert.h>

#ifdef NDEBUG
// glibc conditionally defines __assert dependent on NDEBUG. As such, when
// NDEBUG is declared, we need to ensure that don't try and find the __assert
// function.
#define BINDER_ASSERT(file, line, msg) ((void)file, (void)line, (void)msg)
#else  // Not NDEBUG
#if defined(__BIONIC__)
#define BINDER_ASSERT(file, line, msg) __assert(file, line, msg)
#else
#define BINDER_ASSERT(file, line, msg) __assert(msg, file, line)
#endif

#endif  // Not NDEBUG
