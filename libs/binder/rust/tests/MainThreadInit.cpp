#include <binder/IPCThreadState.h>

namespace {

using namespace android;

// Initialize an IPCThreadState from the main thread, before anyone spins up a
// child thread and initializes thread-local state in binder. Doing this on the
// main thread is necessary so that when libbinder C++ static destructors are
// called, binder has an IPCThreadState already on the main thread. Trying to
// initialize a new IPCThreadstate inside the static destructors was causing
// non-deterministic segfaults, presumably due to use-after-free of static
// globals. This was observed because the Rust test harness always executes
// tests on a child thread while the C++ global static destructors run on the
// main thread.
IPCThreadState* init = IPCThreadState::self();

}; // anonymous namespace
