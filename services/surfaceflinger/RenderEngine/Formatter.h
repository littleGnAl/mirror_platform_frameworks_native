/*
 * Copyright (C) 2019 Samsung Electronics
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

#ifndef SF_RENDER_ENGINE_FORMATTER_H
#define SF_RENDER_ENGINE_FORMATTER_H

#include <stdint.h>
#include <utils/String8.h>

namespace android {

/*
 * A simple formatter class to automatically add the endl and
 * manage the indentation.
 */

class Formatter;

class Formatter {
    String8 mString;
    int mIndent;
    typedef Formatter& (*FormaterManipFunc)(Formatter&);
    friend Formatter& indent(Formatter& f);
    friend Formatter& dedent(Formatter& f);

public:
    Formatter() : mIndent(0) {}

    String8 getString() const { return mString; }

    friend Formatter& operator<<(Formatter& out, const char* in) {
        for (int i = 0; i < out.mIndent; i++) {
            out.mString.append("    ");
        }
        out.mString.append(in);
        out.mString.append("\n");
        return out;
    }
    friend inline Formatter& operator<<(Formatter& out, const String8& in) {
        return operator<<(out, in.string());
    }
    friend inline Formatter& operator<<(Formatter& to, FormaterManipFunc func) {
        return (*func)(to);
    }
};

} /* namespace android */

#endif /* SF_RENDER_ENGINE_FORMATTER_H */
