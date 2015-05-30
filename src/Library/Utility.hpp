#pragma once

#include <cstdint>
#include <time.h>

namespace pgl
{

  uint64_t tsMicrosecDiff(const struct timespec& ts_a, const struct timespec& ts_b);

} /* namespace pgl */
