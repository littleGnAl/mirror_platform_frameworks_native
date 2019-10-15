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

#include <string>

#include <android-base/unique_fd.h>

#ifdef _WIN32

#include <stddef.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#else /* !_WIN32 */

#include <poll.h>
#include <stdio.h>
#include <unistd.h>

#include <cutils/sockets.h>

#endif  /* _WIN32 */

namespace adbwifi {
namespace sysdeps {

#ifdef _WIN32

#define OS_PATH_SEPARATOR '\\'

static __inline__ void close_on_exec(android::base::borrowed_fd /* fd */) {
    /* nothing really */
}

extern int adb_rename(const char* oldpath, const char* newpath);
extern int adb_unlink(const char* path);

extern int adb_open(const char* path, int options);
extern int adb_creat(const char* path, int mode);
extern int adb_read(android::base::borrowed_fd fd, void* buf, int len);
extern int adb_pread(android::base::borrowed_fd fd, void* buf, int len, off64_t offset);
extern int adb_write(android::base::borrowed_fd fd, const void* buf, int len);
extern int adb_pwrite(android::base::borrowed_fd fd, const void* buf, int len, off64_t offset);
extern int adb_close(int fd);
extern HANDLE get_os_handle(android::base::borrowed_fd fd);

struct adb_pollfd {
    int fd;
    short events;
    short revents;
};
extern int adb_poll(adb_pollfd* fds, size_t nfds, int timeout);

int network_inaddr_any_server(int port, int type, std::string* error);
int network_connect(const std::string& host, int port, int type, int timeout,
                    std::string* error);
bool set_file_block_mode(android::base::borrowed_fd fd, bool block);
extern int adb_socketpair(int sv[2]);

#else /* !_WIN32 */

#define OS_PATH_SEPARATOR '/'

static __inline__ void close_on_exec(android::base::borrowed_fd fd) {
    fcntl(fd.get(), F_SETFD, FD_CLOEXEC);
}

static __inline__ int adb_rename(const char* oldpath, const char* newpath) {
    return ::rename(oldpath, newpath);
}

static __inline__ int adb_unlink(const char* path) {
    return ::unlink(path);
}

static __inline__ int get_os_handle(android::base::borrowed_fd fd) {
    return fd.get();
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

bool set_file_block_mode(android::base::borrowed_fd fd, bool block);

static __inline__ int unix_socketpair(int d, int type, int protocol, int sv[2]) {
    return socketpair(d, type, protocol, sv);
}

static __inline__ int adb_socketpair(int sv[2]) {
    int rc;

    rc = unix_socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    if (rc < 0) return -1;

    close_on_exec(sv[0]);
    close_on_exec(sv[1]);
    return 0;
}

#undef socketpair
#define socketpair ___xxx_socketpair

typedef struct ::pollfd adb_pollfd;
static __inline__ int adb_poll(adb_pollfd* fds, size_t nfds, int timeout) {
    return TEMP_FAILURE_RETRY(::poll(fds, nfds, timeout));
}

// Open a file and return a file descriptor that may be used with adb_read(),
// adb_write(), adb_close(), but not unix_read(), unix_write(), unix_close().
//
// On Unix, this is based on open(), but the Windows implementation (in
// sysdeps_win32.cpp) uses Windows native file I/O and bypasses the C Runtime
// and its CR/LF translation. The returned file descriptor should be used with
// adb_read(), adb_write(), adb_close(), etc.
static __inline__ int adb_open(const char* pathname, int options) {
    int fd = TEMP_FAILURE_RETRY(open(pathname, options));
    if (fd < 0) return -1;
    close_on_exec(fd);
    return fd;
}
#undef open
#define open ___xxx_open

// Closes a file descriptor that came from adb_open() or adb_open_mode(), but
// not designed to take a file descriptor from unix_open(). See the comments
// for adb_open() for more info.
__inline__ int adb_close(int fd) {
    return close(fd);
}
#undef close
#define close ____xxx_close

static __inline__ int adb_read(android::base::borrowed_fd fd, void* buf, size_t len) {
    return TEMP_FAILURE_RETRY(read(fd.get(), buf, len));
}

static __inline__ int adb_pread(int fd, void* buf, size_t len, off64_t offset) {
#if defined(__APPLE__)
    return TEMP_FAILURE_RETRY(pread(fd, buf, len, offset));
#else
    return TEMP_FAILURE_RETRY(pread64(fd, buf, len, offset));
#endif
}

#undef read
#define read ___xxx_read
#undef pread
#define pread ___xxx_pread

static __inline__ int adb_write(android::base::borrowed_fd fd, const void* buf, size_t len) {
    return TEMP_FAILURE_RETRY(write(fd.get(), buf, len));
}

static __inline__ int adb_pwrite(int fd, const void* buf, size_t len, off64_t offset) {
#if defined(__APPLE__)
    return TEMP_FAILURE_RETRY(pwrite(fd, buf, len, offset));
#else
    return TEMP_FAILURE_RETRY(pwrite64(fd, buf, len, offset));
#endif
}

#undef   write
#define  write  ___xxx_write
#undef pwrite
#define pwrite ___xxx_pwrite

static __inline__ int adb_creat(const char* path, int mode) {
    int fd = TEMP_FAILURE_RETRY(creat(path, mode));

    if (fd < 0) return -1;

    close_on_exec(fd);
    return fd;
}
#undef creat
#define creat ___xxx_creat

#endif  /* _WIN32 */

}  // namespace sysdeps
}  // namespace adbwifi

#if defined(_WIN32)
// Win32 defines ERROR, which we don't need, but which conflicts with google3
// logging.
#undef ERROR
#endif  /* _WIN32 */
