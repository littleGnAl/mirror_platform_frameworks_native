/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef FRAMEWORK_NATIVE_CMDS_LSHAL_TEXT_TABLE_ROW_H_
#define FRAMEWORK_NATIVE_CMDS_LSHAL_TEXT_TABLE_ROW_H_

#include <iostream>
#include <string>
#include <vector>

#include "TableEntry.h"

namespace android {
namespace lshal {

class TextTableRow {
public:
    TextTableRow() {}
    TextTableRow(std::vector<std::string>&& v) : mFields(std::move(v)) {}
    TextTableRow(std::string&& s) : mLine(std::move(s)) {}
    TextTableRow(const std::string& s) : mLine(s) {}
    const std::vector<std::string>& fields() const { return mFields; }
    const std::string& line() const { return mLine; }

private:
    std::vector<std::string> mFields;
    std::string mLine;
};

class TextTable {
public:
    void add() { mTable.emplace_back(); }
    void add(std::vector<std::string>&& v) {
        computeWidth(v);
        mTable.emplace_back(std::move(v));
    }
    void add(const std::string& s) { mTable.emplace_back(s); }
    void add(std::string&& s) { mTable.emplace_back(std::move(s)); }
    void dump(std::ostream& out) const;

private:
    void computeWidth(const std::vector<std::string>& v);
    std::vector<size_t> mWidths;
    std::vector<TextTableRow> mTable;
};

} // namespace lshal
} // namespace android

#endif // FRAMEWORK_NATIVE_CMDS_LSHAL_TEXT_TABLE_ROW_H_
