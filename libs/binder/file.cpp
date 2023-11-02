/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <binder/file.h>

// clang-format off

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#if defined(_WIN32)
#include <direct.h>
#include <windows.h>
#endif

namespace android {
namespace base {

bool ReadFdToString(borrowed_fd fd, std::string* content) {
  content->clear();

  // Although original we had small files in mind, this code gets used for
  // very large files too, where the std::string growth heuristics might not
  // be suitable. https://code.google.com/p/android/issues/detail?id=258500.
  struct stat sb;
  if (fstat(fd.get(), &sb) != -1 && sb.st_size > 0) {
    content->reserve(sb.st_size);
  }

  char buf[4096] __attribute__((__uninitialized__));
  ssize_t n;
  while ((n = TEMP_FAILURE_RETRY(read(fd.get(), &buf[0], sizeof(buf)))) > 0) {
    content->append(buf, n);
  }
  return (n == 0) ? true : false;
}

bool WriteStringToFd(std::string_view content, borrowed_fd fd) {
  const char* p = content.data();
  size_t left = content.size();
  while (left > 0) {
    ssize_t n = TEMP_FAILURE_RETRY(write(fd.get(), p, left));
    if (n == -1) {
      return false;
    }
    p += n;
    left -= n;
  }
  return true;
}

bool ReadFully(borrowed_fd fd, void* data, size_t byte_count) {
  uint8_t* p = reinterpret_cast<uint8_t*>(data);
  size_t remaining = byte_count;
  while (remaining > 0) {
    ssize_t n = TEMP_FAILURE_RETRY(read(fd.get(), p, remaining));
    if (n <= 0) return false;
    p += n;
    remaining -= n;
  }
  return true;
}

bool WriteFully(borrowed_fd fd, const void* data, size_t byte_count) {
  const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
  size_t remaining = byte_count;
  while (remaining > 0) {
    ssize_t n = TEMP_FAILURE_RETRY(write(fd.get(), p, remaining));
    if (n == -1) return false;
    p += n;
    remaining -= n;
  }
  return true;
}

#if !defined(_WIN32)
bool Readlink(const std::string& path, std::string* result) {
  result->clear();

  // Most Linux file systems (ext2 and ext4, say) limit symbolic links to
  // 4095 bytes. Since we'll copy out into the string anyway, it doesn't
  // waste memory to just start there. We add 1 so that we can recognize
  // whether it actually fit (rather than being truncated to 4095).
  std::vector<char> buf(4095 + 1);
  while (true) {
    ssize_t size = readlink(path.c_str(), &buf[0], buf.size());
    // Unrecoverable error?
    if (size == -1) return false;
    // It fit! (If size == buf.size(), it may have been truncated.)
    if (static_cast<size_t>(size) < buf.size()) {
      result->assign(&buf[0], size);
      return true;
    }
    // Double our buffer and try again.
    buf.resize(buf.size() * 2);
  }
}
#endif

std::string GetExecutablePath() {
#if defined(__linux__)
  std::string path;
  android::base::Readlink("/proc/self/exe", &path);
  return path;
#elif defined(__APPLE__)
  char path[PATH_MAX + 1];
  uint32_t path_len = sizeof(path);
  int rc = _NSGetExecutablePath(path, &path_len);
  if (rc < 0) {
    std::unique_ptr<char> path_buf(new char[path_len]);
    _NSGetExecutablePath(path_buf.get(), &path_len);
    return path_buf.get();
  }
  return path;
#elif defined(_WIN32)
  char path[PATH_MAX + 1];
  DWORD result = GetModuleFileName(NULL, path, sizeof(path) - 1);
  if (result == 0 || result == sizeof(path) - 1) return "";
  path[PATH_MAX - 1] = 0;
  return path;
#elif defined(__EMSCRIPTEN__)
  abort();
#else
#error unknown OS
#endif
}

std::string GetExecutableDirectory() {
  return Dirname(GetExecutablePath());
}

#if defined(_WIN32)
std::string Basename(std::string_view path) {
  // TODO: how much of this is actually necessary for mingw?

  // Copy path because basename may modify the string passed in.
  std::string result(path);

  // Use lock because basename() may write to a process global and return a
  // pointer to that. Note that this locking strategy only works if all other
  // callers to basename in the process also grab this same lock, but its
  // better than nothing.  Bionic's basename returns a thread-local buffer.
  static std::mutex& basename_lock = *new std::mutex();
  std::lock_guard<std::mutex> lock(basename_lock);

  // Note that if std::string uses copy-on-write strings, &str[0] will cause
  // the copy to be made, so there is no chance of us accidentally writing to
  // the storage for 'path'.
  char* name = basename(&result[0]);

  // In case basename returned a pointer to a process global, copy that string
  // before leaving the lock.
  result.assign(name);

  return result;
}
#else
// Copied from bionic so that Basename() below can be portable and thread-safe.
static int _basename_r(const char* path, size_t path_size, char* buffer, size_t buffer_size) {
  const char* startp = nullptr;
  const char* endp = nullptr;
  int len;
  int result;

  // Empty or NULL string gets treated as ".".
  if (path == nullptr || path_size == 0) {
    startp = ".";
    len = 1;
    goto Exit;
  }

  // Strip trailing slashes.
  endp = path + path_size - 1;
  while (endp > path && *endp == '/') {
    endp--;
  }

  // All slashes becomes "/".
  if (endp == path && *endp == '/') {
    startp = "/";
    len = 1;
    goto Exit;
  }

  // Find the start of the base.
  startp = endp;
  while (startp > path && *(startp - 1) != '/') {
    startp--;
  }

  len = endp - startp +1;

 Exit:
  result = len;
  if (buffer == nullptr) {
    return result;
  }
  if (len > static_cast<int>(buffer_size) - 1) {
    len = buffer_size - 1;
    result = -1;
    errno = ERANGE;
  }

  if (len >= 0) {
    memcpy(buffer, startp, len);
    buffer[len] = 0;
  }
  return result;
}
std::string Basename(std::string_view path) {
  char buf[PATH_MAX] __attribute__((__uninitialized__));
  const auto size = _basename_r(path.data(), path.size(), buf, sizeof(buf));
  return size > 0 ? std::string(buf, size) : std::string();
}
#endif

#if defined(_WIN32)
std::string Dirname(std::string_view path) {
  // TODO: how much of this is actually necessary for mingw?

  // Copy path because dirname may modify the string passed in.
  std::string result(path);

  // Use lock because dirname() may write to a process global and return a
  // pointer to that. Note that this locking strategy only works if all other
  // callers to dirname in the process also grab this same lock, but its
  // better than nothing.  Bionic's dirname returns a thread-local buffer.
  static std::mutex& dirname_lock = *new std::mutex();
  std::lock_guard<std::mutex> lock(dirname_lock);

  // Note that if std::string uses copy-on-write strings, &str[0] will cause
  // the copy to be made, so there is no chance of us accidentally writing to
  // the storage for 'path'.
  char* parent = dirname(&result[0]);

  // In case dirname returned a pointer to a process global, copy that string
  // before leaving the lock.
  result.assign(parent);

  return result;
}
#else
// Copied from bionic so that Dirname() below can be portable and thread-safe.
static int _dirname_r(const char* path, size_t path_size, char* buffer, size_t buffer_size) {
  const char* endp = nullptr;
  int len;
  int result;

  // Empty or NULL string gets treated as ".".
  if (path == nullptr || path_size == 0) {
    path = ".";
    len = 1;
    goto Exit;
  }

  // Strip trailing slashes.
  endp = path + path_size - 1;
  while (endp > path && *endp == '/') {
    endp--;
  }

  // Find the start of the dir.
  while (endp > path && *endp != '/') {
    endp--;
  }

  // Either the dir is "/" or there are no slashes.
  if (endp == path) {
    path = (*endp == '/') ? "/" : ".";
    len = 1;
    goto Exit;
  }

  do {
    endp--;
  } while (endp > path && *endp == '/');

  len = endp - path + 1;

 Exit:
  result = len;
  if (len + 1 > MAXPATHLEN) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (buffer == nullptr) {
    return result;
  }

  if (len > static_cast<int>(buffer_size) - 1) {
    len = buffer_size - 1;
    result = -1;
    errno = ERANGE;
  }

  if (len >= 0) {
    memcpy(buffer, path, len);
    buffer[len] = 0;
  }
  return result;
}
std::string Dirname(std::string_view path) {
  char buf[PATH_MAX] __attribute__((__uninitialized__));
  const auto size = _dirname_r(path.data(), path.size(), buf, sizeof(buf));
  return size > 0 ? std::string(buf, size) : std::string();
}
#endif

}  // namespace base
}  // namespace android
