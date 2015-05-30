#include "Utility.hpp"

namespace pgl
{

  uint64_t tsMicrosecDiff(const struct timespec& ts_a, const struct timespec& ts_b)
  {
    const uint64_t ns_abs_a = ts_a.tv_sec * 1000 * 1000 * 1000 + ts_a.tv_nsec;
    const uint64_t ns_abs_b = ts_b.tv_sec * 1000 * 1000 * 1000 + ts_b.tv_nsec;
    const uint64_t ns_diff = (ns_abs_a > ns_abs_b ?
			      ns_abs_a - ns_abs_b : ns_abs_b - ns_abs_a);
    return ns_diff / 1000;
  }

} /* namespace pgl */
