NewServiceManager - WIP
=======================


Overview
--------
This module is a new implementation of the Android ServiceManager that uses
the binder API provided through libbinder.so, instead of directly talking
with the binder kernel driver through its ioctl() interface.

This enables us to move away from a direct interaction with the kernel
driver and as of when this module will replace the "old" servicemanager,
if ever, the only Android userspace interaction with the Kernel Binder
module will be libbinder.so. This will facilitate any attempts of
replacing the default Android IPC mechanism, binder, with something
else, by replacing libbinder.so with another implementation that
provides the same public API (please note that a complete replacement of
libbinder is at least a order of magnitude more difficult since the Java
API relies on the functionality provided).

This is far from being complete and, for the time being, it should not be used
for purposes other than testing!


Known Limitations
-----------------
Current limitations:
 * No SELinux hooks - but libbinder provides an interface for easily adding
   security hooks.
 * The death notification mechanism is not fully working, at the very
   least we are not removing the dead binder from the service list.
 * Limited testing.


TODOs
-----
All of the above plus an extensive gtest suite and thorough documentation.

Ideas for the tests:
 * Add/get/check/listService.
 * Add an existing service.
 * Death notification clean-up.


Test Environment
----------------
This module has been tested using bctest and binderAddInts. It is known to boot
to GUI on the Android ARM64 emulator. The easiest way to test is to replace
/system/bin/servicemanager with this module.
