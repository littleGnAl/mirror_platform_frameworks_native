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

namespace adbwifi {
namespace compat {
#ifdef _WIN32

#include <stddef.h>

#define OS_PATH_SEPARATOR '\\'

extern int rename(const char* oldpath, const char* newpath);
extern int unlink(const char* path);
int network_inaddr_any_server(int port, int type, std::string* error);
int network_connect(const std::string& host, int port, int type, int timeout,
                    std::string* error);

#else /* !_WIN32 */

#define OS_PATH_SEPARATOR '/'

#include <stdio.h>

#include <cutils/sockets.h>

static __inline__ int rename(const char* oldpath, const char* newpath) {
    return ::rename(oldpath, newpath);
}

static __inline__ int unlink(const char* path) {
    return ::unlink(path);
}

// Helper for network_* functions.
inline int _fd_set_error_str(int fd, std::string* error) {
    if (fd == -1) {
        *error = strerror(errno);
    }
    return fd;
}

inline int network_inaddr_any_server(int port, int type, std::string* error) {
    return _fd_set_error_str(socket_inaddr_any_server(port, type), error);
}

int network_connect(const std::string& host, int port, int type, int timeout, std::string* error);

#endif

}  // namespace compat
}  // namespace adbwifi
