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

int my_rename(const char* oldpath, const char* newpath) {
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
int my_unlink(const char* path) {
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

int my_gethostname(char* name, size_t len) {
    const char* computerName = adb_getenv("COMPUTERNAME");
    if (computerName && !isBlankStr(computerName)) {
        strncpy(name, computerName, len);
        name[len - 1] = '\0';
        return 0;
    }

    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer);
    if (!GetComputerNameW(buffer, &size)) {
        return -1;
    }
    std::string name_utf8;
    if (!android::base::WideToUTF8(buffer, &name_utf8)) {
        return -1;
    }

    strncpy(name, name_utf8.c_str(), len);
    name[len - 1] = '\0';
    return 0;
}

int my_getlogin_r(char* buf, size_t bufsize) {
    wchar_t buffer[UNLEN + 1];
    DWORD len = sizeof(buffer);
    if (!GetUserNameW(buffer, &len)) {
        return -1;
    }

    std::string login;
    if (!android::base::WideToUTF8(buffer, &login)) {
        return -1;
    }

    strncpy(buf, login.c_str(), bufsize);
    buf[bufsize - 1] = '\0';
    return 0;
}

