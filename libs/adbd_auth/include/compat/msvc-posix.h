/*
 * Copyright (C) 2019 The Android Open Source Project
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

// TODO: Possible to move the system/core/adb/sysdeps.h code into android-base
// library?

#ifdef _WIN32

#define OS_PATH_SEPARATOR '\\'

extern int my_rename(const char* oldpath, const char* newpath);
extern int my_unlink(const char* path);
extern int my_gethostname(char* name, size_t len);
extern int my_getlogin_r(char* buf, size_t bufsize);

#else /* !_WIN32 */

#define OS_PATH_SEPARATOR '/'

#include <stdio.h>

static __inline__ int my_rename(const char* oldpath, const char* newpath) {
    return rename(oldpath, newpath);
}

static __inline__ int my_unlink(const char* path) {
    return unlink(path);
}

static __inline__ int my_gethostname(char* name, size_t len) {
    return gethostname(name, len);
}

static __inline__ int my_getlogin_r(char* buf, size_t bufsize) {
    return getlogin_r(buf, bufsize);
}
#endif
