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

#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

namespace pgl
{
  /*
   * Close all file descriptors starting from `from_fd` up to the current
   * RLIMIT_NOFILE resource value.
   */
  void closeAllFDs(int from_fd);

  /*
   * Send a file descriptor over the `bus_fd`. Returns 0 on success and -1 in case of a failure.
   */
  int writeFD(int bus_fd, int fd, unsigned int max_delay_usec);
  int readFD(int bus_fd, unsigned int max_delay_usec);

  /*
   * Get/set process resource limits.
   * Throws SyscallError on error.
   */
  rlim_t getResourceLimit(int resource);
  void setResourceLimit(int resource, rlim_t limit);

} /* namespace pgl */
