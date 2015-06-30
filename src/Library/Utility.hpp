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
#pragma once

#include <cstdint>
#include <time.h>

namespace pgl
{
  /*
   * Close all file descriptors starting from `from_fd` up to the current
   * RLIMIT_NOFILE resource value.
   */
  void closeAllFDs(int from_fd);

  /*
   * Microsecond difference between two points in time stored in a timespec structure.
   */
  uint64_t tsMicrosecDiff(const struct timespec& ts_a, const struct timespec& ts_b);

  int writeFD(int bus_fd, int fd, unsigned int max_delay_usec);
  int readFD(int bus_fd, unsigned int max_delay_usec);

} /* namespace pgl */
