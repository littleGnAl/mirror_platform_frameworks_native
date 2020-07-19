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

#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include "BufferedTextOutput.h"

#define UNUSED(expr)  \
    do {              \
        (void)(expr); \
    } while (0)

namespace android {

class FuzzBufferedTextOutput : public BufferedTextOutput {
public:
    FuzzBufferedTextOutput(uint32_t flags) : BufferedTextOutput(flags) {}
    virtual status_t writeLines(const struct iovec& vec, size_t N) {
        UNUSED(vec);
        UNUSED(N);
        return status_t();
    }
};

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    std::unique_ptr<BufferedTextOutput> b_text_output =
            std::unique_ptr<BufferedTextOutput>(new FuzzBufferedTextOutput(flags));

    while (fdp.remaining_bytes() > 1) {
        switch (fdp.ConsumeIntegral<uint8_t>() % 4) {
            case 0: {
                b_text_output->pushBundle();
                break;
            }
            case 1: {
                std::string txt = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
                size_t len = fdp.ConsumeIntegralInRange<size_t>(0, txt.length());
                b_text_output->print(txt.c_str(), len);
                break;
            }
            case 2: {
                int delta = fdp.ConsumeIntegralInRange<int>(0, 1024);
                b_text_output->moveIndent(delta);
                break;
            }
            case 3: {
                b_text_output->popBundle();
            }
        }
    }

    return 0;
}
} // namespace android
