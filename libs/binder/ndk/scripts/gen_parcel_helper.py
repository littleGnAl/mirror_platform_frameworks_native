#!/usr/bin/env python3

import os
import sys


# list (pretty, cpp)
data_types = [
    ("Int32", "int32_t"),
    ("Uint32", "uint32_t"),
    ("Int64", "int64_t"),
    ("Uint64", "uint64_t"),
    ("Float", "float"),
    ("Double", "double"),
    ("Bool", "bool"),
    ("Char", "char16_t"),
    ("Byte", "int8_t"),
]

def replaceFileTags(path, content):
    print("Updating", path)
    with open(path, "r+") as f:
        lines = f.readlines()

        start = lines.index("// @START\n")
        end = lines.index("// @END\n")

        if end <= start or start < 0 or end < 0:
            print("Failed to find tags in", path)
            exit(1)

        f.seek(0)
        f.write("".join(lines[:start+1]) + content + "".join(lines[end:]))
        f.truncate()

def main():
    if len(sys.argv) != 1:
        print("No arguments.")
        exit(1)

    ABT = os.environ.get('ANDROID_BUILD_TOP', None)
    if ABT is None:
        print("Can't get ANDROID_BUILD_TOP. Lunch?")
        exit(1)
    ROOT = ABT + "/frameworks/native/libs/binder/ndk/"

    print("Updating auto-generated code")

    header = ""
    source = ""

    for pretty, cpp in data_types:
        header += "transport_status_t AParcel_write" + pretty + "(AParcel* parcel, " + cpp + " value);\n"
        source += "transport_status_t AParcel_write" + pretty + "(AParcel* parcel, " + cpp + " value) {\n"
        source += "    return (*parcel)->write" + pretty + "(value);\n"
        source += "}\n"

    for pretty, cpp in data_types:
        header += "transport_status_t AParcel_read" + pretty + "(AParcel* parcel, " + cpp + "* value);\n"
        source += "transport_status_t AParcel_read" + pretty + "(AParcel* parcel, " + cpp + "* value) {\n"
        source += "    return (*parcel)->read" + pretty + "(value);\n"
        source += "}\n"

    replaceFileTags(ROOT + "include_ndk/binder/AParcel.h", header)
    replaceFileTags(ROOT + "AParcel.cpp", source)

    print("Updating DONE.")

if __name__ == "__main__":
    main()
