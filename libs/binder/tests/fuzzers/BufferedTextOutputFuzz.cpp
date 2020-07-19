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

#include <BufferedTextOutputFuzzFunctions.h>
#include <commonFuzzHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "BufferedTextOutput.h"

namespace android {

class FuzzBufferedTextOutput : public BufferedTextOutput {
public:
    FuzzBufferedTextOutput(uint32_t flags) : BufferedTextOutput(flags) {}
    virtual status_t writeLines(const struct iovec& buf, size_t) {
        size_t len = buf.iov_len;
        void* tmp_buf = malloc(len);

        if (tmp_buf == NULL) {
            return status_t();
        }

        // This will attempt to read data from iov_base to ensure valid params were passed.
        memcpy(tmp_buf, buf.iov_base, len);
        free(tmp_buf);
        return status_t();
    }
};

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    std::shared_ptr<BufferedTextOutput> b_text_output(new FuzzBufferedTextOutput(flags));

    while (fdp.remaining_bytes() > 0) {
        callArbitraryFunction(&fdp, gBufferedTextOutputOperations, b_text_output);
    }

    kPushCount = 0;
    return 0;
}
} // namespace android
