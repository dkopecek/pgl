//
// Copyright (C) 2015 Red Hat, Inc.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Authors: Daniel Kopecek <dkopecek@redhat.com>
//
#include "Utility.hpp"
#include <sys/resource.h>
#include <unistd.h>

namespace pgl
{
  void closeAllFDs(int from_fd)
  { 
    int fd_max = 1024;
    struct rlimit limit;

    if (getrlimit(RLIMIT_NOFILE, &limit) == 0) {
      fd_max = limit.rlim_cur - 1;
    }

    for (int fd = from_fd; fd <= fd_max; ++fd) {
      close(fd);
    }

    return;
  }

  uint64_t tsMicrosecDiff(const struct timespec& ts_a, const struct timespec& ts_b)
  {
    const uint64_t ns_abs_a = ts_a.tv_sec * 1000 * 1000 * 1000 + ts_a.tv_nsec;
    const uint64_t ns_abs_b = ts_b.tv_sec * 1000 * 1000 * 1000 + ts_b.tv_nsec;
    const uint64_t ns_diff = (ns_abs_a > ns_abs_b ?
			      ns_abs_a - ns_abs_b : ns_abs_b - ns_abs_a);
    return ns_diff / 1000;
  }
} /* namespace pgl */
