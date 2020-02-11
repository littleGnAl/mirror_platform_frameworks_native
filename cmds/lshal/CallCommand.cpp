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

#include "CallCommand.h"

#include <hidl-util/FQName.h>
#include <stdlib.h>

#include "Lshal.h"

namespace android {
namespace lshal {

using hardware::Parcel;

std::string CallCommand::getName() const {
    return "call";
}

std::string CallCommand::getSimpleDescription() const {
    return "Call a HAL method over Binder (similar to `service call`).";
}

Status CallCommand::parseArgs(const Arg& arg) {
    if (optind >= arg.argc) {
        mLshal.err() << "lshal: no service name supplied for call\n\n";
        return USAGE;
    }

    std::string interfaceName = arg.argv[optind];
    ++optind;
    auto pair = splitFirst(interfaceName, '/');
    FQName fqName;
    if (!FQName::parse(pair.first, &fqName) || fqName.isIdentifier() ||
        !fqName.isFullyQualified()) {
        mLshal.err() << "Invalid fully-qualified name '" << pair.first << "'\n\n";
        return USAGE;
    }
    mInterfaceDescriptor = pair.first;
    mInterfaceInstance = pair.second.empty() ? "default" : pair.second;

    // hwbinder expects us to write the interface name first (or enforceInterface would fail).
    mData.writeInterfaceToken(mInterfaceDescriptor.c_str());

    if (optind >= arg.argc) {
        mLshal.err() << "lshal: no service code supplied for call\n\n";
        return USAGE;
    }
    mCode = atoi(arg.argv[optind]);
    ++optind;

    // The binder arguments are optional.
    while (optind < arg.argc) {
        // Adapted from ../service/service.cpp's argument parsing.
        if (strcmp(arg.argv[optind], "i32") == 0) {
            ++optind;
            if (optind >= arg.argc) {
                mLshal.err() << "lshal: no integer supplied for 'i32'\n\n";
                return USAGE;
            }
            mData.writeInt32(atoi(arg.argv[optind]));
        } else if (strcmp(arg.argv[optind], "i64") == 0) {
            ++optind;
            if (optind >= arg.argc) {
                mLshal.err() << "lshal: no integer supplied for 'i64'\n\n";
                return USAGE;
            }
            mData.writeInt64(atoll(arg.argv[optind]));
        } else if (strcmp(arg.argv[optind], "s16") == 0) {
            ++optind;
            if (optind >= arg.argc) {
                mLshal.err() << "lshal: no string supplied for 's16'\n\n";
                return USAGE;
            }
            mData.writeString16(String16(arg.argv[optind]));
        } else if (strcmp(arg.argv[optind], "f") == 0) {
            ++optind;
            if (optind >= arg.argc) {
                mLshal.err() << "lshal: no number supplied for 'f'\n\n";
                return USAGE;
            }
            mData.writeFloat(atof(arg.argv[optind]));
        } else if (strcmp(arg.argv[optind], "d") == 0) {
            ++optind;
            if (optind >= arg.argc) {
                mLshal.err() << "lshal: no number supplied for 'd'\n\n";
                return USAGE;
            }
            mData.writeDouble(atof(arg.argv[optind]));
        } else if (strcmp(arg.argv[optind], "b") == 0) {
            ++optind;
            if (optind >= arg.argc) {
                mLshal.err() << "lshal: no value supplied for 'b'\n\n";
                return USAGE;
            }
            bool value;
            if (strcmp(arg.argv[optind], "0") == 0 || strcmp(arg.argv[optind], "f") == 0 ||
                strcmp(arg.argv[optind], "false") == 0) {
                value = false;
            } else if (strcmp(arg.argv[optind], "1") == 0 || strcmp(arg.argv[optind], "t") == 0 ||
                       strcmp(arg.argv[optind], "true") == 0) {
                value = true;
            } else {
                mLshal.err() << "lshal: unrecognized value supplied for 'b': '" << arg.argv[optind]
                             << "'\n\n";
                return USAGE;
            }
            mData.writeBool(value);
        } else {
            // TODO handle? structs? more complex stuff?
            mLshal.err() << "lshal: unknown option '" << arg.argv[optind] << "'\n\n";
            return USAGE;
        }
        ++optind;
    }
    return OK;
}

Status CallCommand::main(const Arg& arg) {
    Status status = parseArgs(arg);
    if (status != OK) {
        return status;
    }

    return mLshal.call(mInterfaceDescriptor, mInterfaceInstance, mCode, mData, mLshal.out(),
                       mLshal.err());
}

void CallCommand::usage() const {
    static const std::string call =
            "call:\n"
            "    lshal call <interface> <code> [ i32 N | i64 N | f N | d N | b B | s16 STR ] ...\n"
            "        <interface>: Format is `android.hardware.foo@1.0::IFoo/default`.\n"
            "            If instance name is missing `default` is used.\n"
            "        options:\n"
            "            i32: Write the 32-bit integer N into the send parcel.\n"
            "            i64: Write the 64-bit integer N into the send parcel.\n"
            "            f:   Write the 32-bit single-precision number N into the send parcel.\n"
            "            d:   Write the 64-bit double-precision number N into the send parcel.\n"
            "            b:   Write the boolean value B into the send parcel.\n"
            "            s16: Write the UTF-16 string STR into the send parcel.\n";

    mLshal.err() << call;
}

} // namespace lshal
} // namespace android
