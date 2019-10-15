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

#include "adbwifi/sysdeps/sysdeps.h"

#include <winsock2.h> /* winsock.h *must* be included before windows.h. */
#include <windows.h>
#include <lmcons.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <cutils/sockets.h>

#include <android-base/errors.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/utf8.h>

#include "adbwifi/sysdeps/uio.h"

namespace adbwifi {
namespace sysdeps {

using android::base::borrowed_fd;

/* forward declarations */

typedef const struct FHClassRec_* FHClass;
typedef struct FHRec_* FH;

typedef struct FHClassRec_ {
    void (*_fh_init)(FH);
    int (*_fh_close)(FH);
    int64_t (*_fh_lseek)(FH, int64_t, int);
    int (*_fh_read)(FH, void*, int);
    int (*_fh_write)(FH, const void*, int);
    int (*_fh_writev)(FH, const adb_iovec*, int);
    intptr_t (*_fh_get_os_handle)(FH);
} FHClassRec;

static void _fh_file_init(FH);
static int _fh_file_close(FH);
static int64_t _fh_file_lseek(FH, int64_t, int);
static int _fh_file_read(FH, void*, int);
static int _fh_file_write(FH, const void*, int);
static int _fh_file_writev(FH, const adb_iovec*, int);
static intptr_t _fh_file_get_os_handle(FH f);

static const FHClassRec _fh_file_class = {
        _fh_file_init,  _fh_file_close,  _fh_file_lseek,         _fh_file_read,
        _fh_file_write, _fh_file_writev, _fh_file_get_os_handle,
};

static void _fh_socket_init(FH);
static int _fh_socket_close(FH);
static int64_t _fh_socket_lseek(FH, int64_t, int);
static int _fh_socket_read(FH, void*, int);
static int _fh_socket_write(FH, const void*, int);
static int _fh_socket_writev(FH, const adb_iovec*, int);
static intptr_t _fh_socket_get_os_handle(FH f);

static const FHClassRec _fh_socket_class = {
        _fh_socket_init,  _fh_socket_close,  _fh_socket_lseek,         _fh_socket_read,
        _fh_socket_write, _fh_socket_writev, _fh_socket_get_os_handle,
};

#if defined(assert)
#undef assert
#endif

//void handle_deleter::operator()(HANDLE h) {
//    // CreateFile() is documented to return INVALID_HANDLE_FILE on error,
//    // implying that NULL is a valid handle, but this is probably impossible.
//    // Other APIs like CreateEvent() are documented to return NULL on error,
//    // implying that INVALID_HANDLE_VALUE is a valid handle, but this is also
//    // probably impossible. Thus, consider both NULL and INVALID_HANDLE_VALUE
//    // as invalid handles. std::unique_ptr won't call a deleter with NULL, so we
//    // only need to check for INVALID_HANDLE_VALUE.
//    if (h != INVALID_HANDLE_VALUE) {
//        if (!CloseHandle(h)) {
//            LOG(INFO) << android::base::StringPrintf("CloseHandle(%p) failed: %s", h,
//              android::base::SystemErrorCodeToString(GetLastError()).c_str());
//        }
//    }
//}

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    common file descriptor handling                             *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

typedef struct FHRec_
{
    FHClass    clazz;
    int        used;
    int        eof;
    union {
        HANDLE      handle;
        SOCKET      socket;
    } u;

    char  name[32];
} FHRec;

#define  fh_handle  u.handle
#define  fh_socket  u.socket

#define  WIN32_FH_BASE    2048
#define  WIN32_MAX_FHS    2048

static  std::mutex&  _win32_lock = *new std::mutex();
static  FHRec        _win32_fhs[ WIN32_MAX_FHS ];
static  int          _win32_fh_next;  // where to start search for free FHRec

static FH _fh_from_int(borrowed_fd bfd, const char* func) {
    FH f;

    int fd = bfd.get();
    fd -= WIN32_FH_BASE;

    if (fd < 0 || fd >= WIN32_MAX_FHS) {
        LOG(INFO) << android::base::StringPrintf("_fh_from_int: invalid fd %d passed to %s", fd + WIN32_FH_BASE, func);
        errno = EBADF;
        return nullptr;
    }

    f = &_win32_fhs[fd];

    if (f->used == 0) {
        LOG(INFO) << android::base::StringPrintf("_fh_from_int: invalid fd %d passed to %s", fd + WIN32_FH_BASE, func);
        errno = EBADF;
        return nullptr;
    }

    return f;
}

static int _fh_to_int(FH f) {
    if (f && f->used && f >= _win32_fhs && f < _win32_fhs + WIN32_MAX_FHS)
        return (int)(f - _win32_fhs) + WIN32_FH_BASE;

    return -1;
}

static FH _fh_alloc(FHClass clazz) {
    FH f = nullptr;

    std::lock_guard<std::mutex> lock(_win32_lock);

    for (int i = _win32_fh_next; i < WIN32_MAX_FHS; ++i) {
        if (_win32_fhs[i].clazz == nullptr) {
            f = &_win32_fhs[i];
            _win32_fh_next = i + 1;
            f->clazz = clazz;
            f->used = 1;
            f->eof = 0;
            f->name[0] = '\0';
            clazz->_fh_init(f);
            return f;
        }
    }

    LOG(INFO) << android::base::StringPrintf("_fh_alloc: no more free file descriptors");
    errno = EMFILE;  // Too many open files
    return nullptr;
}

static int _fh_close(FH f) {
    // Use lock so that closing only happens once and so that _fh_alloc can't
    // allocate a FH that we're in the middle of closing.
    std::lock_guard<std::mutex> lock(_win32_lock);

    int offset = f - _win32_fhs;
    if (_win32_fh_next > offset) {
        _win32_fh_next = offset;
    }

    if (f->used) {
        f->clazz->_fh_close( f );
        f->name[0] = '\0';
        f->eof     = 0;
        f->used    = 0;
        f->clazz   = nullptr;
    }
    return 0;
}

// Deleter for unique_fh.
class fh_deleter {
 public:
  void operator()(struct FHRec_* fh) {
    // We're called from a destructor and destructors should not overwrite
    // errno because callers may do:
    //   errno = EBLAH;
    //   return -1; // calls destructor, which should not overwrite errno
    const int saved_errno = errno;
    _fh_close(fh);
    errno = saved_errno;
  }
};

// Like std::unique_ptr, but calls _fh_close() instead of operator delete().
typedef std::unique_ptr<struct FHRec_, fh_deleter> unique_fh;

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    file-based descriptor handling                              *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

static void _fh_file_init(FH f) {
    f->fh_handle = INVALID_HANDLE_VALUE;
}

static int _fh_file_close(FH f) {
    CloseHandle(f->fh_handle);
    f->fh_handle = INVALID_HANDLE_VALUE;
    return 0;
}

static int _fh_file_read(FH f, void* buf, int len) {
    DWORD read_bytes;

    if (!ReadFile(f->fh_handle, buf, (DWORD)len, &read_bytes, nullptr)) {
        LOG(INFO) << android::base::StringPrintf("read: could not read %d bytes from %s", len, f->name);
        errno = EIO;
        return -1;
    } else if (read_bytes < (DWORD)len) {
        f->eof = 1;
    }
    return read_bytes;
}

static int _fh_file_write(FH f, const void* buf, int len) {
    DWORD wrote_bytes;

    if (!WriteFile(f->fh_handle, buf, (DWORD)len, &wrote_bytes, nullptr)) {
        LOG(INFO) << android::base::StringPrintf("adb_file_write: could not write %d bytes from %s", len, f->name);
        errno = EIO;
        return -1;
    } else if (wrote_bytes < (DWORD)len) {
        f->eof = 1;
    }
    return wrote_bytes;
}

static int _fh_file_writev(FH f, const adb_iovec* iov, int iovcnt) {
    if (iovcnt <= 0) {
        errno = EINVAL;
        return -1;
    }

    DWORD wrote_bytes = 0;

    for (int i = 0; i < iovcnt; ++i) {
        ssize_t rc = _fh_file_write(f, iov[i].iov_base, iov[i].iov_len);
        if (rc == -1) {
            return wrote_bytes > 0 ? wrote_bytes : -1;
        } else if (rc == 0) {
            return wrote_bytes;
        }

        wrote_bytes += rc;

        if (static_cast<size_t>(rc) < iov[i].iov_len) {
            return wrote_bytes;
        }
    }

    return wrote_bytes;
}

static int64_t _fh_file_lseek(FH f, int64_t pos, int origin) {
    DWORD method;
    switch (origin) {
        case SEEK_SET:
            method = FILE_BEGIN;
            break;
        case SEEK_CUR:
            method = FILE_CURRENT;
            break;
        case SEEK_END:
            method = FILE_END;
            break;
        default:
            errno = EINVAL;
            return -1;
    }

    LARGE_INTEGER li = {.QuadPart = pos};
    if (!SetFilePointerEx(f->fh_handle, li, &li, method)) {
        errno = EIO;
        return -1;
    }
    f->eof = 0;
    return li.QuadPart;
}

static intptr_t _fh_file_get_os_handle(FH f) {
    return reinterpret_cast<intptr_t>(f->u.handle);
}

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    file-based descriptor handling                              *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

int adb_open(const char* path, int options) {
    FH f;

    DWORD desiredAccess = 0;
    DWORD shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;

    // CreateFileW is inherently O_CLOEXEC by default.
    options &= ~O_CLOEXEC;

    switch (options) {
        case O_RDONLY:
            desiredAccess = GENERIC_READ;
            break;
        case O_WRONLY:
            desiredAccess = GENERIC_WRITE;
            break;
        case O_RDWR:
            desiredAccess = GENERIC_READ | GENERIC_WRITE;
            break;
        default:
            LOG(INFO) << android::base::StringPrintf("adb_open: invalid options (0x%0x)", options);
            errno = EINVAL;
            return -1;
    }

    f = _fh_alloc(&_fh_file_class);
    if (!f) {
        return -1;
    }

    std::wstring path_wide;
    if (!android::base::UTF8ToWide(path, &path_wide)) {
        return -1;
    }
    f->fh_handle =
        CreateFileW(path_wide.c_str(), desiredAccess, shareMode, nullptr, OPEN_EXISTING, 0, nullptr);

    if (f->fh_handle == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        _fh_close(f);
        LOG(INFO) << android::base::StringPrintf("adb_open: could not open '%s': ", path);
        switch (err) {
            case ERROR_FILE_NOT_FOUND:
                LOG(INFO) << android::base::StringPrintf("file not found");
                errno = ENOENT;
                return -1;

            case ERROR_PATH_NOT_FOUND:
                LOG(INFO) << android::base::StringPrintf("path not found");
                errno = ENOTDIR;
                return -1;

            default:
                LOG(INFO) << android::base::StringPrintf("unknown error: %s", android::base::SystemErrorCodeToString(err).c_str());
                errno = ENOENT;
                return -1;
        }
    }

    snprintf(f->name, sizeof(f->name), "%d(%s)", _fh_to_int(f), path);
    LOG(INFO) << android::base::StringPrintf("adb_open: '%s' => fd %d", path, _fh_to_int(f));
    return _fh_to_int(f);
}

int adb_read(borrowed_fd fd, void* buf, int len) {
    FH f = _fh_from_int(fd, __func__);

    if (f == nullptr) {
        errno = EBADF;
        return -1;
    }

    return f->clazz->_fh_read(f, buf, len);
}

int adb_pread(borrowed_fd fd, void* buf, int len, off64_t offset) {
    OVERLAPPED overlapped = {};
    overlapped.Offset = static_cast<DWORD>(offset);
    overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32);
    DWORD bytes_read;
    if (!::ReadFile(get_os_handle(fd), buf, static_cast<DWORD>(len), &bytes_read,
                    &overlapped)) {
        LOG(INFO) << android::base::StringPrintf("pread: could not read %d bytes from FD %d", len, fd.get());
        switch (::GetLastError()) {
            case ERROR_IO_PENDING:
                errno = EAGAIN;
                return -1;
            default:
                errno = EINVAL;
                return -1;
        }
    }
    return static_cast<int>(bytes_read);
}

int adb_write(borrowed_fd fd, const void* buf, int len) {
    FH f = _fh_from_int(fd, __func__);

    if (f == nullptr) {
        errno = EBADF;
        return -1;
    }

    return f->clazz->_fh_write(f, buf, len);
}

ssize_t adb_writev(borrowed_fd fd, const adb_iovec* iov, int iovcnt) {
    FH f = _fh_from_int(fd, __func__);

    if (f == nullptr) {
        errno = EBADF;
        return -1;
    }

    return f->clazz->_fh_writev(f, iov, iovcnt);
}

int adb_pwrite(borrowed_fd fd, const void* buf, int len, off64_t offset) {
    OVERLAPPED params = {};
    params.Offset = static_cast<DWORD>(offset);
    params.OffsetHigh = static_cast<DWORD>(offset >> 32);
    DWORD bytes_written = 0;
    if (!::WriteFile(get_os_handle(fd), buf, len, &bytes_written, &params)) {
        LOG(INFO) << android::base::StringPrintf("adb_pwrite: could not write %d bytes to FD %d", len, fd.get());
        switch (::GetLastError()) {
            case ERROR_IO_PENDING:
                errno = EAGAIN;
                return -1;
            default:
                errno = EINVAL;
                return -1;
        }
    }
    return static_cast<int>(bytes_written);
}

int close(int fd) {
    FH f = _fh_from_int(fd, __func__);

    if (!f) {
        errno = EBADF;
        return -1;
    }

    LOG(INFO) << android::base::StringPrintf("close: %s", f->name);
    _fh_close(f);
    return 0;
}

HANDLE get_os_handle(borrowed_fd fd) {
    FH f = _fh_from_int(fd, __func__);

    if (!f) {
        errno = EBADF;
        return nullptr;
    }

    LOG(INFO) << android::base::StringPrintf("get_os_handle: %s", f->name);
    const intptr_t intptr_handle = f->clazz->_fh_get_os_handle(f);
    const HANDLE handle = reinterpret_cast<const HANDLE>(intptr_handle);
    return handle;
}

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    socket-based file descriptors                               *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

#undef setsockopt

static void _socket_set_errno( const DWORD err ) {
    // Because the Windows C Runtime (MSVCRT.DLL) strerror() does not support a
    // lot of POSIX and socket error codes, some of the resulting error codes
    // are mapped to strings by adb_strerror().
    switch ( err ) {
    case 0:              errno = 0; break;
    // Don't map WSAEINTR since that is only for Winsock 1.1 which we don't use.
    // case WSAEINTR:    errno = EINTR; break;
    case WSAEFAULT:      errno = EFAULT; break;
    case WSAEINVAL:      errno = EINVAL; break;
    case WSAEMFILE:      errno = EMFILE; break;
    // Mapping WSAEWOULDBLOCK to EAGAIN is absolutely critical because
    // non-blocking sockets can cause an error code of WSAEWOULDBLOCK and
    // callers check specifically for EAGAIN.
    case WSAEWOULDBLOCK: errno = EAGAIN; break;
    case WSAENOTSOCK:    errno = ENOTSOCK; break;
    case WSAENOPROTOOPT: errno = ENOPROTOOPT; break;
    case WSAEOPNOTSUPP:  errno = EOPNOTSUPP; break;
    case WSAENETDOWN:    errno = ENETDOWN; break;
    case WSAENETRESET:   errno = ENETRESET; break;
    // Map WSAECONNABORTED to EPIPE instead of ECONNABORTED because POSIX seems
    // to use EPIPE for these situations and there are some callers that look
    // for EPIPE.
    case WSAECONNABORTED: errno = EPIPE; break;
    case WSAECONNRESET:  errno = ECONNRESET; break;
    case WSAENOBUFS:     errno = ENOBUFS; break;
    case WSAENOTCONN:    errno = ENOTCONN; break;
    // Don't map WSAETIMEDOUT because we don't currently use SO_RCVTIMEO or
    // SO_SNDTIMEO which would cause WSAETIMEDOUT to be returned. Future
    // considerations: Reportedly send() can return zero on timeout, and POSIX
    // code may expect EAGAIN instead of ETIMEDOUT on timeout.
    // case WSAETIMEDOUT: errno = ETIMEDOUT; break;
    case WSAEHOSTUNREACH: errno = EHOSTUNREACH; break;
    default:
        errno = EINVAL;
        LOG(INFO) << android::base::StringPrintf( "_socket_set_errno: mapping Windows error code %lu to errno %d",
           err, errno );
    }
}

extern int adb_poll(adb_pollfd* fds, size_t nfds, int timeout) {
    // WSAPoll doesn't handle invalid/non-socket handles, so we need to handle them ourselves.
    int skipped = 0;
    std::vector<WSAPOLLFD> sockets;
    std::vector<adb_pollfd*> original;

    for (size_t i = 0; i < nfds; ++i) {
        FH fh = _fh_from_int(fds[i].fd, __func__);
        if (!fh || !fh->used || fh->clazz != &_fh_socket_class) {
            LOG(INFO) << android::base::StringPrintf("adb_poll received bad FD %d", fds[i].fd);
            fds[i].revents = POLLNVAL;
            ++skipped;
        } else {
            WSAPOLLFD wsapollfd = {
                .fd = fh->u.socket,
                .events = static_cast<short>(fds[i].events)
            };
            sockets.push_back(wsapollfd);
            original.push_back(&fds[i]);
        }
    }

    if (sockets.empty()) {
        return skipped;
    }

    // If we have any invalid FDs in our FD set, make sure to return immediately.
    if (skipped > 0) {
        timeout = 0;
    }

    int result = WSAPoll(sockets.data(), sockets.size(), timeout);
    if (result == SOCKET_ERROR) {
        _socket_set_errno(WSAGetLastError());
        return -1;
    }

    // Map the results back onto the original set.
    for (size_t i = 0; i < sockets.size(); ++i) {
        original[i]->revents = sockets[i].revents;
    }

    // WSAPoll appears to return the number of unique FDs with available events, instead of how many
    // of the adb_pollfd elements have a non-zero revents field, which is what it and poll are specified
    // to do. Ignore its result and calculate the proper return value.
    result = 0;
    for (size_t i = 0; i < nfds; ++i) {
        if (fds[i].revents != 0) {
            ++result;
        }
    }
    return result;
}

static void _fh_socket_init(FH f) {
    f->fh_socket = INVALID_SOCKET;
}

static int _fh_socket_close(FH f) {
    if (f->fh_socket != INVALID_SOCKET) {
        if (closesocket(f->fh_socket) == SOCKET_ERROR) {
            // Don't set errno here, since close will ignore it.
            const DWORD err = WSAGetLastError();
            LOG(INFO) << android::base::StringPrintf("closesocket failed: %s", android::base::SystemErrorCodeToString(err).c_str());
        }
        f->fh_socket = INVALID_SOCKET;
    }
    return 0;
}

static int64_t _fh_socket_lseek(FH /* f */, int64_t /* pos */, int /* origin */) {
    errno = EPIPE;
    return -1;
}

static int _fh_socket_read(FH f, void* buf, int len) {
    int result = recv(f->fh_socket, reinterpret_cast<char*>(buf), len, 0);
    if (result == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        // WSAEWOULDBLOCK is normal with a non-blocking socket, so don't trace
        // that to reduce spam and confusion.
        if (err != WSAEWOULDBLOCK) {
            LOG(INFO) << android::base::StringPrintf("recv fd %d failed: %s", _fh_to_int(f),
              android::base::SystemErrorCodeToString(err).c_str());
        }
        _socket_set_errno(err);
        result = -1;
    }
    return result;
}

static int _fh_socket_write(FH f, const void* buf, int len) {
    int result = send(f->fh_socket, reinterpret_cast<const char*>(buf), len, 0);
    if (result == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        // WSAEWOULDBLOCK is normal with a non-blocking socket, so don't trace
        // that to reduce spam and confusion.
        if (err != WSAEWOULDBLOCK) {
            LOG(INFO) << android::base::StringPrintf("send fd %d failed: %s", _fh_to_int(f),
              android::base::SystemErrorCodeToString(err).c_str());
        }
        _socket_set_errno(err);
        result = -1;
    } else {
        // According to https://code.google.com/p/chromium/issues/detail?id=27870
        // Winsock Layered Service Providers may cause this.
        CHECK_LE(result, len) << "Tried to write " << len << " bytes to " << f->name << ", but "
                              << result << " bytes reportedly written";
    }
    return result;
}

// Make sure that adb_iovec is compatible with WSABUF.
static_assert(sizeof(adb_iovec) == sizeof(WSABUF), "");
static_assert(SIZEOF_MEMBER(adb_iovec, iov_len) == SIZEOF_MEMBER(WSABUF, len), "");
static_assert(offsetof(adb_iovec, iov_len) == offsetof(WSABUF, len), "");

static_assert(SIZEOF_MEMBER(adb_iovec, iov_base) == SIZEOF_MEMBER(WSABUF, buf), "");
static_assert(offsetof(adb_iovec, iov_base) == offsetof(WSABUF, buf), "");

static int _fh_socket_writev(FH f, const adb_iovec* iov, int iovcnt) {
    if (iovcnt <= 0) {
        errno = EINVAL;
        return -1;
    }

    WSABUF* wsabuf = reinterpret_cast<WSABUF*>(const_cast<adb_iovec*>(iov));
    DWORD bytes_written = 0;
    int result = WSASend(f->fh_socket, wsabuf, iovcnt, &bytes_written, 0, nullptr, nullptr);
    if (result == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        // WSAEWOULDBLOCK is normal with a non-blocking socket, so don't trace
        // that to reduce spam and confusion.
        if (err != WSAEWOULDBLOCK) {
            LOG(INFO) << android::base::StringPrintf("send fd %d failed: %s", _fh_to_int(f),
              android::base::SystemErrorCodeToString(err).c_str());
        }
        _socket_set_errno(err);
        return -1;
    }
    CHECK_GE(static_cast<DWORD>(std::numeric_limits<int>::max()), bytes_written);
    return static_cast<int>(bytes_written);
}

static intptr_t _fh_socket_get_os_handle(FH f) {
    return f->u.socket;
}

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    replacement for libs/cutils/socket_xxxx.c                   *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

// Map a socket type to an explicit socket protocol instead of using the socket
// protocol of 0. Explicit socket protocols are used by most apps and we should
// do the same to reduce the chance of exercising uncommon code-paths that might
// have problems or that might load different Winsock service providers that
// have problems.
static int GetSocketProtocolFromSocketType(int type) {
    switch (type) {
        case SOCK_STREAM:
            return IPPROTO_TCP;
        case SOCK_DGRAM:
            return IPPROTO_UDP;
        default:
            LOG(FATAL) << "Unknown socket type: " << type;
            return 0;
    }
}

int network_loopback_client(int port, int type, std::string* error) {
    struct sockaddr_in addr;
    SOCKET s;

    unique_fh f(_fh_alloc(&_fh_socket_class));
    if (!f) {
        *error = strerror(errno);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    s = socket(AF_INET, type, GetSocketProtocolFromSocketType(type));
    if (s == INVALID_SOCKET) {
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot create socket: %s",
                                             android::base::SystemErrorCodeToString(err).c_str());
        LOG(INFO) << android::base::StringPrintf("%s", error->c_str());
        _socket_set_errno(err);
        return -1;
    }
    f->fh_socket = s;

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        // Save err just in case inet_ntoa() or ntohs() changes the last error.
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot connect to %s:%u: %s",
                                             inet_ntoa(addr.sin_addr), ntohs(addr.sin_port),
                                             android::base::SystemErrorCodeToString(err).c_str());
        LOG(INFO) << android::base::StringPrintf("could not connect to %s:%d: %s", type != SOCK_STREAM ? "udp" : "tcp", port,
          error->c_str());
        _socket_set_errno(err);
        return -1;
    }

    const int fd = _fh_to_int(f.get());
    snprintf(f->name, sizeof(f->name), "%d(lo-client:%s%d)", fd, type != SOCK_STREAM ? "udp:" : "",
             port);
    LOG(INFO) << android::base::StringPrintf("port %d type %s => fd %d", port, type != SOCK_STREAM ? "udp" : "tcp", fd);
    f.release();
    return fd;
}

// interface_address is INADDR_LOOPBACK or INADDR_ANY.
static int _network_server(int port, int type, u_long interface_address, std::string* error) {
    struct sockaddr_in addr;
    SOCKET s;
    int n;

    unique_fh f(_fh_alloc(&_fh_socket_class));
    if (!f) {
        *error = strerror(errno);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(interface_address);

    // TODO: Consider using dual-stack socket that can simultaneously listen on
    // IPv4 and IPv6.
    s = socket(AF_INET, type, GetSocketProtocolFromSocketType(type));
    if (s == INVALID_SOCKET) {
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot create socket: %s",
                                             android::base::SystemErrorCodeToString(err).c_str());
        LOG(INFO) << android::base::StringPrintf("%s", error->c_str());
        _socket_set_errno(err);
        return -1;
    }

    f->fh_socket = s;

    // Note: SO_REUSEADDR on Windows allows multiple processes to bind to the
    // same port, so instead use SO_EXCLUSIVEADDRUSE.
    n = 1;
    if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&n, sizeof(n)) == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot set socket option SO_EXCLUSIVEADDRUSE: %s",
                                             android::base::SystemErrorCodeToString(err).c_str());
        LOG(INFO) << android::base::StringPrintf("%s", error->c_str());
        _socket_set_errno(err);
        return -1;
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        // Save err just in case inet_ntoa() or ntohs() changes the last error.
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot bind to %s:%u: %s", inet_ntoa(addr.sin_addr),
                                             ntohs(addr.sin_port),
                                             android::base::SystemErrorCodeToString(err).c_str());
        LOG(INFO) << android::base::StringPrintf("could not bind to %s:%d: %s", type != SOCK_STREAM ? "udp" : "tcp", port, error->c_str());
        _socket_set_errno(err);
        return -1;
    }
    if (type == SOCK_STREAM) {
        if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
            const DWORD err = WSAGetLastError();
            *error = android::base::StringPrintf(
                "cannot listen on socket: %s", android::base::SystemErrorCodeToString(err).c_str());
            LOG(INFO) << android::base::StringPrintf("could not listen on %s:%d: %s", type != SOCK_STREAM ? "udp" : "tcp", port,
              error->c_str());
            _socket_set_errno(err);
            return -1;
        }
    }
    const int fd = _fh_to_int(f.get());
    snprintf(f->name, sizeof(f->name), "%d(%s-server:%s%d)", fd,
             interface_address == INADDR_LOOPBACK ? "lo" : "any", type != SOCK_STREAM ? "udp:" : "",
             port);
    LOG(INFO) << android::base::StringPrintf("port %d type %s => fd %d", port, type != SOCK_STREAM ? "udp" : "tcp", fd);
    f.release();
    return fd;
}

int network_loopback_server(int port, int type, std::string* error) {
    return _network_server(port, type, INADDR_LOOPBACK, error);
}

int network_inaddr_any_server(int port, int type, std::string* error) {
    return _network_server(port, type, INADDR_ANY, error);
}

int network_connect(const std::string& host, int port, int type, int /* timeout */, std::string* error) {
    unique_fh f(_fh_alloc(&_fh_socket_class));
    if (!f) {
        *error = strerror(errno);
        return -1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type;
    hints.ai_protocol = GetSocketProtocolFromSocketType(type);

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo* addrinfo_ptr = nullptr;

#if (NTDDI_VERSION >= NTDDI_WINXPSP2) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
// TODO: When the Android SDK tools increases the Windows system
// requirements >= WinXP SP2, switch to android::base::UTF8ToWide() + GetAddrInfoW().
#else
// Otherwise, keep using getaddrinfo(), or do runtime API detection
// with GetProcAddress("GetAddrInfoW").
#endif
    if (getaddrinfo(host.c_str(), port_str, &hints, &addrinfo_ptr) != 0) {
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot resolve host '%s' and port %s: %s",
                                             host.c_str(), port_str,
                                             android::base::SystemErrorCodeToString(err).c_str());

        LOG(INFO) << android::base::StringPrintf("%s", error->c_str());
        _socket_set_errno(err);
        return -1;
    }
    std::unique_ptr<struct addrinfo, decltype(&freeaddrinfo)> addrinfo(addrinfo_ptr, freeaddrinfo);
    addrinfo_ptr = nullptr;

    // TODO: Try all the addresses if there's more than one? This just uses
    // the first. Or, could call WSAConnectByName() (Windows Vista and newer)
    // which tries all addresses, takes a timeout and more.
    SOCKET s = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if (s == INVALID_SOCKET) {
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot create socket: %s",
                                             android::base::SystemErrorCodeToString(err).c_str());
        LOG(INFO) << android::base::StringPrintf("%s", error->c_str());
        _socket_set_errno(err);
        return -1;
    }
    f->fh_socket = s;

    // TODO: Implement timeouts for Windows. Seems like the default in theory
    // (according to http://serverfault.com/a/671453) and in practice is 21 sec.
    if (connect(s, addrinfo->ai_addr, addrinfo->ai_addrlen) == SOCKET_ERROR) {
        // TODO: Use WSAAddressToString or inet_ntop on address.
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot connect to %s:%s: %s", host.c_str(), port_str,
                                             android::base::SystemErrorCodeToString(err).c_str());
        LOG(INFO) << android::base::StringPrintf("could not connect to %s:%s:%s: %s", type != SOCK_STREAM ? "udp" : "tcp", host.c_str(),
          port_str, error->c_str());
        _socket_set_errno(err);
        return -1;
    }

    const int fd = _fh_to_int(f.get());
    snprintf(f->name, sizeof(f->name), "%d(net-client:%s%d)", fd, type != SOCK_STREAM ? "udp:" : "",
             port);
    LOG(INFO) << android::base::StringPrintf("host '%s' port %d type %s => fd %d", host.c_str(), port, type != SOCK_STREAM ? "udp" : "tcp",
      fd);
    f.release();
    return fd;
}

int adb_register_socket(SOCKET s) {
    FH f = _fh_alloc(&_fh_socket_class);
    f->fh_socket = s;
    return _fh_to_int(f);
}

#undef accept
int adb_socket_accept(borrowed_fd serverfd, struct sockaddr* addr, socklen_t* addrlen) {
    FH serverfh = _fh_from_int(serverfd, __func__);

    if (!serverfh || serverfh->clazz != &_fh_socket_class) {
        LOG(INFO) << android::base::StringPrintf("adb_socket_accept: invalid fd %d", serverfd.get());
        errno = EBADF;
        return -1;
    }

    unique_fh fh(_fh_alloc(&_fh_socket_class));
    if (!fh) {
        PLOG(ERROR) << "adb_socket_accept: failed to allocate accepted socket "
                       "descriptor";
        return -1;
    }

    fh->fh_socket = accept(serverfh->fh_socket, addr, addrlen);
    if (fh->fh_socket == INVALID_SOCKET) {
        const DWORD err = WSAGetLastError();
        LOG(ERROR) << "adb_socket_accept: accept on fd " << serverfd.get()
                   << " failed: " + android::base::SystemErrorCodeToString(err);
        _socket_set_errno(err);
        return -1;
    }

    const int fd = _fh_to_int(fh.get());
    snprintf(fh->name, sizeof(fh->name), "%d(accept:%s)", fd, serverfh->name);
    LOG(INFO) << android::base::StringPrintf("adb_socket_accept on fd %d returns fd %d", serverfd.get(), fd);
    fh.release();
    return fd;
}

int adb_setsockopt(borrowed_fd fd, int level, int optname, const void* optval, socklen_t optlen) {
    FH fh = _fh_from_int(fd, __func__);

    if (!fh || fh->clazz != &_fh_socket_class) {
        LOG(INFO) << android::base::StringPrintf("adb_setsockopt: invalid fd %d", fd.get());
        errno = EBADF;
        return -1;
    }

    // TODO: Once we can assume Windows Vista or later, if the caller is trying
    // to set SOL_SOCKET, SO_SNDBUF/SO_RCVBUF, ignore it since the OS has
    // auto-tuning.

    int result =
        setsockopt(fh->fh_socket, level, optname, reinterpret_cast<const char*>(optval), optlen);
    if (result == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        LOG(INFO) << android::base::StringPrintf("adb_setsockopt: setsockopt on fd %d level %d optname %d failed: %s\n", fd.get(), level,
          optname, android::base::SystemErrorCodeToString(err).c_str());
        _socket_set_errno(err);
        result = -1;
    }
    return result;
}

static int adb_getsockname(borrowed_fd fd, struct sockaddr* sockaddr, socklen_t* optlen) {
    FH fh = _fh_from_int(fd, __func__);

    if (!fh || fh->clazz != &_fh_socket_class) {
        LOG(INFO) << android::base::StringPrintf("adb_getsockname: invalid fd %d", fd.get());
        errno = EBADF;
        return -1;
    }

    int result = getsockname(fh->fh_socket, sockaddr, optlen);
    if (result == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        LOG(INFO) << android::base::StringPrintf("adb_getsockname: setsockopt on fd %d failed: %s\n", fd.get(),
          android::base::SystemErrorCodeToString(err).c_str());
        _socket_set_errno(err);
        result = -1;
    }
    return result;
}

int adb_socket_get_local_port(borrowed_fd fd) {
    sockaddr_storage addr_storage;
    socklen_t addr_len = sizeof(addr_storage);

    if (adb_getsockname(fd, reinterpret_cast<sockaddr*>(&addr_storage), &addr_len) < 0) {
        LOG(INFO) << android::base::StringPrintf("adb_socket_get_local_port: adb_getsockname failed: %s", strerror(errno));
        return -1;
    }

    if (!(addr_storage.ss_family == AF_INET || addr_storage.ss_family == AF_INET6)) {
        LOG(INFO) << android::base::StringPrintf("adb_socket_get_local_port: unknown address family received: %d", addr_storage.ss_family);
        errno = ECONNABORTED;
        return -1;
    }

    return ntohs(reinterpret_cast<sockaddr_in*>(&addr_storage)->sin_port);
}

int adb_shutdown(borrowed_fd fd, int direction) {
    FH f = _fh_from_int(fd, __func__);

    if (!f || f->clazz != &_fh_socket_class) {
        LOG(INFO) << android::base::StringPrintf("adb_shutdown: invalid fd %d", fd.get());
        errno = EBADF;
        return -1;
    }

    LOG(INFO) << android::base::StringPrintf("adb_shutdown: %s", f->name);
    if (shutdown(f->fh_socket, direction) == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        LOG(INFO) << android::base::StringPrintf("socket shutdown fd %d failed: %s", fd.get(),
          android::base::SystemErrorCodeToString(err).c_str());
        _socket_set_errno(err);
        return -1;
    }
    return 0;
}

// Emulate socketpair(2) by binding and connecting to a socket.
int adb_socketpair(int sv[2]) {
    int server = -1;
    int client = -1;
    int accepted = -1;
    int local_port = -1;
    std::string error;

    server = network_loopback_server(0, SOCK_STREAM, &error);
    if (server < 0) {
        LOG(INFO) << android::base::StringPrintf("adb_socketpair: failed to create server: %s", error.c_str());
        goto fail;
    }

    local_port = adb_socket_get_local_port(server);
    if (local_port < 0) {
        LOG(INFO) << android::base::StringPrintf("adb_socketpair: failed to get server port number: %s", error.c_str());
        goto fail;
    }
    LOG(INFO) << android::base::StringPrintf("adb_socketpair: bound on port %d", local_port);

    client = network_loopback_client(local_port, SOCK_STREAM, &error);
    if (client < 0) {
        LOG(INFO) << android::base::StringPrintf("adb_socketpair: failed to connect client: %s", error.c_str());
        goto fail;
    }

    accepted = adb_socket_accept(server, nullptr, nullptr);
    if (accepted < 0) {
        LOG(INFO) << android::base::StringPrintf("adb_socketpair: failed to accept: %s", strerror(errno));
        goto fail;
    }
    close(server);
    sv[0] = client;
    sv[1] = accepted;
    return 0;

fail:
    if (server >= 0) {
        close(server);
    }
    if (client >= 0) {
        close(client);
    }
    if (accepted >= 0) {
        close(accepted);
    }
    return -1;
}

bool set_file_block_mode(borrowed_fd fd, bool block) {
    FH fh = _fh_from_int(fd, __func__);

    if (!fh || !fh->used) {
        errno = EBADF;
        LOG(INFO) << android::base::StringPrintf("Setting nonblocking on bad file descriptor %d", fd.get());
        return false;
    }

    if (fh->clazz == &_fh_socket_class) {
        u_long x = !block;
        if (ioctlsocket(fh->u.socket, FIONBIO, &x) != 0) {
            int error = WSAGetLastError();
            _socket_set_errno(error);
            LOG(INFO) << android::base::StringPrintf("Setting %d nonblocking failed (%d)", fd.get(), error);
            return false;
        }
        return true;
    } else {
        errno = ENOTSOCK;
        LOG(INFO) << android::base::StringPrintf("Setting nonblocking on non-socket %d", fd.get());
        return false;
    }
}

bool set_tcp_keepalive(borrowed_fd fd, int interval_sec) {
    FH fh = _fh_from_int(fd, __func__);

    if (!fh || fh->clazz != &_fh_socket_class) {
        LOG(INFO) << android::base::StringPrintf("set_tcp_keepalive(%d) failed: invalid fd", fd.get());
        errno = EBADF;
        return false;
    }

    tcp_keepalive keepalive;
    keepalive.onoff = (interval_sec > 0);
    keepalive.keepalivetime = interval_sec * 1000;
    keepalive.keepaliveinterval = interval_sec * 1000;

    DWORD bytes_returned = 0;
    if (WSAIoctl(fh->fh_socket, SIO_KEEPALIVE_VALS, &keepalive, sizeof(keepalive), nullptr, 0,
                 &bytes_returned, nullptr, nullptr) != 0) {
        const DWORD err = WSAGetLastError();
        LOG(INFO) << android::base::StringPrintf("set_tcp_keepalive(%d) failed: %s", fd.get(),
          android::base::SystemErrorCodeToString(err).c_str());
        _socket_set_errno(err);
        return false;
    }

    return true;
}

// Version of unlink() that takes a UTF-8 path.
int adb_unlink(const char* path) {
    std::wstring wpath;
    if (!android::base::UTF8ToWide(path, &wpath)) {
        return -1;
    }

    int  rc = _wunlink(wpath.c_str());

    if (rc == -1 && errno == EACCES) {
        /* unlink returns EACCES when the file is read-only, so we first */
        /* try to make it writable, then unlink again...                 */
        rc = _wchmod(wpath.c_str(), _S_IREAD | _S_IWRITE);
        if (rc == 0)
            rc = _wunlink(wpath.c_str());
    }
    return rc;
}

int adb_rename(const char* oldpath, const char* newpath) {
    std::wstring oldpath_wide, newpath_wide;
    if (!android::base::UTF8ToWide(oldpath, &oldpath_wide)) {
        return -1;
    }
    if (!android::base::UTF8ToWide(newpath, &newpath_wide)) {
        return -1;
    }

    // MSDN just says the return value is non-zero on failure, make sure it
    // returns -1 on failure so that it behaves the same as other systems.
    return ::_wrename(oldpath_wide.c_str(), newpath_wide.c_str()) ? -1 : 0;
}

// Version of chmod() that takes a UTF-8 path.
int adb_chmod(const char* path, int mode) {
    std::wstring path_wide;
    if (!android::base::UTF8ToWide(path, &path_wide)) {
        return -1;
    }

    return ::_wchmod(path_wide.c_str(), mode);
}

}  // namespace sysdeps
}  // namespace adbwifi
