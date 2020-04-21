#include "throughput_bindings.h"

namespace cxx_timing {

chrono::time_point<chrono::high_resolution_clock>* create_time_point() {
  return new chrono::time_point<chrono::high_resolution_clock>;
}
void now(chrono::time_point<chrono::high_resolution_clock> *time) {
  *time = chrono::high_resolution_clock::now();
}
uint64_t nanosecond_diff(chrono::time_point<chrono::high_resolution_clock> *start,
                         chrono::time_point<chrono::high_resolution_clock> *end) {
  return chrono::duration_cast<chrono::nanoseconds>(*end - *start).count();
}

}
