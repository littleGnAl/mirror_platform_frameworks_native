#include <chrono>
using namespace std;

namespace cxx_timing {
chrono::time_point<chrono::high_resolution_clock>* create_time_point();
void now(chrono::time_point<chrono::high_resolution_clock> *time);
uint64_t nanosecond_diff(chrono::time_point<chrono::high_resolution_clock> *start,
                         chrono::time_point<chrono::high_resolution_clock> *end);
}
