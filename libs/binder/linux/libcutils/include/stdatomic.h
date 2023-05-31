#pragma once

// If we could change libcutils, we would just put these two lines instead of
// stdatomic.h include in trace.h.
#include <atomic>
using std::atomic_bool;
