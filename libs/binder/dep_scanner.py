#!/usr/bin/env python3
# TODO: header

import os
import sys

PUBLIC_ROOTS = [
    "frameworks/native/libs/binder/include/binder/Binder.h",
    "frameworks/native/libs/binder/include/binder/BpBinder.h",
    "frameworks/native/libs/binder/include/binder/Enums.h",
    "frameworks/native/libs/binder/include/binder/IBinder.h",
    "frameworks/native/libs/binder/include/binder/IInterface.h",
    "frameworks/native/libs/binder/include/binder/Parcel.h",
    "frameworks/native/libs/binder/include/binder/ParcelFileDescriptor.h",
    "frameworks/native/libs/binder/include/binder/Parcelable.h",
    "frameworks/native/libs/binder/include/binder/ProcessState.h",
    "frameworks/native/libs/binder/include/binder/RpcServer.h",
    "frameworks/native/libs/binder/include/binder/RpcSession.h",
    "frameworks/native/libs/binder/include/binder/RpcTransport.h",
    "frameworks/native/libs/binder/include/binder/RpcTransportRaw.h",
    "frameworks/native/libs/binder/include/binder/Stability.h",
    "frameworks/native/libs/binder/include/binder/Status.h",
]

BINDER_ROOTS = [
    "frameworks/native/libs/binder/Binder.cpp",
    "frameworks/native/libs/binder/BpBinder.cpp",
    "frameworks/native/libs/binder/IInterface.cpp",
    "frameworks/native/libs/binder/Parcel.cpp",
    "frameworks/native/libs/binder/ParcelFileDescriptor.cpp",
    "frameworks/native/libs/binder/ProcessState.cpp",
    "frameworks/native/libs/binder/RpcServer.cpp",
    "frameworks/native/libs/binder/RpcSession.cpp",
    "frameworks/native/libs/binder/RpcState.cpp",
    "frameworks/native/libs/binder/RpcState.h",
    "frameworks/native/libs/binder/RpcWireFormat.h",
    "frameworks/native/libs/binder/RpcTransportRaw.cpp",
    "frameworks/native/libs/binder/Stability.cpp",
    "frameworks/native/libs/binder/Status.cpp",
]

INCLUDE_PATHS = {
    "binder": "frameworks/native/libs/binder",
    "android-base": "system/libbase",
    "cutils": "system/core/libcutils",
    "utils": "system/core/libutils",
    "log": "system/logging/liblog",
    "private": "system/logging/liblog",
    "system": "system/core/libsystem",
    "fmt": "external/fmtlib",
    "backtrace": "system/unwinding/libbacktrace",
    "unwindstack": "system/unwinding/libunwindstack",
    "art_api": "art/libdexfile/external",
    "procinfo": "system/libprocinfo",
    "async_safe": "bionic/libc/async_safe",
    "vndksupport": "system/core/libvndksupport",
    "processgroup": "system/core/libprocessgroup",
}

HARDCODED_HEADERS = {
    "android/log.h": "system/logging/liblog/include/android/log.h",
    "android/fdsan.h": None,
    "mach-o/dyld.h": None,
    "android/set_abort_message.h": "bionic/libc/include/android/set_abort_message.h",
    "bionic/pac.h": "bionic/libc/platform/bionic/pac.h",
    "android/dlext.h": None,
    "linux/android/binder.h": "bionic/libc/kernel/uapi/linux/android/binder.h",
    "android_runtime/vm.h": None,
    "android/os/BnServiceCallback.h": None,
    "android/os/IServiceManager.h": None,
    "private/android_filesystem_config.h": None,
}

SYSTEM_TOPDIRS = [
    "sys",
    "linux",
    "arpa",
    "netinet",
]

class Scanner:
  def __init__(self, aosp_dir):
    self.aosp_dir = aosp_dir
    self.scanned = set()

  def resolve_header(self, header, cur_dir):
    if header[0] == '<':
      include_quote = False
    elif header[0] == '"':
      include_quote = True
    else:
      raise f"Invalid header include: {header}"

    header = header[1:-1]
    if header in HARDCODED_HEADERS:
      return HARDCODED_HEADERS[header]

    comps = header.split('/')
    if not comps:
      return None

    if len(comps) == 1:
      if include_quote:
        actual_header = os.path.join(cur_dir, header)
        if os.path.exists(actual_header):
          return os.path.relpath(actual_header, self.aosp_dir)

      return None

    top = comps[0]
    if top in SYSTEM_TOPDIRS:
      # System header
      return None

    if top in INCLUDE_PATHS:
      top_include = INCLUDE_PATHS[top]
      actual_header = os.path.join(top_include, "include", header)
    else:
      raise Exception(f"Unknown top include path: {header}")

    return actual_header


  def scan(self, paths):
    stk = [p for p in paths]
    self.scanned |= set(stk)
    while stk:
      p = stk.pop()

      file_path = os.path.join(self.aosp_dir, p)
      with open(file_path, 'r') as f:
        for line in f:
          words = line.split()
          if not words or words[0] != "#include":
            continue

          header = words[1]
          actual_header = self.resolve_header(header, os.path.dirname(file_path))
          if actual_header and actual_header not in self.scanned:
            stk.append(actual_header)
            self.scanned.add(actual_header)

            root, ext = os.path.splitext(actual_header)
            assert ext == ".h"
            cpp_file = root + ".cpp"
            if os.path.exists(os.path.join(self.aosp_dir, cpp_file)):
              stk.append(cpp_file)
              self.scanned.add(cpp_file)

            inc_dir = os.path.dirname(actual_header)
            while inc_dir and inc_dir != "/" and os.path.basename(inc_dir) != "include":
              inc_dir = os.path.dirname(inc_dir)

            if os.path.basename(inc_dir) == "include":
              cpp_dir = os.path.dirname(inc_dir)
              cpp_file = os.path.join(cpp_dir, os.path.basename(cpp_file))
              if os.path.exists(os.path.join(self.aosp_dir, cpp_file)):
                stk.append(cpp_file)
                self.scanned.add(cpp_file)

def main(argv):
  if len(argv) != 2:
    print("Usage: dep_scanner.py /path/to/aosp")
    sys.exit(1)

  scanner = Scanner(argv[1])
  scanner.scan(PUBLIC_ROOTS)
  public_files = [h for h in scanner.scanned]

  scanner.scan(BINDER_ROOTS)
  private_files = [h for h in scanner.scanned if h not in public_files]

  public_files.sort()
  for f in public_files:
    print(f"Public,{f}")

  private_files.sort()
  for f in private_files:
    print(f"Private,{f}")

if __name__ == '__main__':
  main(sys.argv)
