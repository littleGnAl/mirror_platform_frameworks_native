/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <binder/AIBinder.h>

struct IFoo {
    static const char* kSomeInstanceName;

    // Takes ownership of IFoo
    static AIBinder* newLocalBinder(IFoo* foo);

    static IFoo* getService(const char* instance);

    enum Call {
        DOFOO = FIRST_CALL_TRANSACTION + 0,
    };

    virtual ~IFoo() = default;
    virtual int32_t doubleNumber(int32_t in) = 0;
};