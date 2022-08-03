// TODO: The C++ stdlib in the Trusty kernel currently doesn't support ostream
// which the CHECK macro defined in android-base/logging.h requires. This header
// redefines this macro as a temporary workaround and should be replaced with
// the original logging.h
#include_next <android-base/logging.h>
#undef CHECK
#define CHECK(x)
