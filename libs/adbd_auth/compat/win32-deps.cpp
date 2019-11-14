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

#include "compat/msvc-posix.h"

#include <winsock2.h> /* winsock.h *must* be included before windows.h. */
#include <windows.h>
//#include <lmcons.h>
#include <sys/stat.h>

//#include <ctype.h>
#include <errno.h>

#include <string>

#include <android-base/utf8.h>

namespace adbwifi {
namespace compat {
int rename(const char* oldpath, const char* newpath) {
    std::wstring oldpath_wide, newpath_wide;
    if (!android::base::UTF8ToWide(oldpath, &oldpath_wide)) {
        return -1;
    }
    if (!android::base::UTF8ToWide(newpath, &newpath_wide)) {
        return -1;
    }

    // MSDN just says the return value is non-zero on failure. make sure it
    // returns -1 on failure so that it behaves the same as other systems.
    return _wrename(oldpath_wide.c_str(), newpath_wide.c_str()) ? -1 : 0;
}

// Version of unlink() that takes a UTF-8 path.
int unlink(const char* path) {
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

}  // namespace compat
}  // namespace adbwifi
