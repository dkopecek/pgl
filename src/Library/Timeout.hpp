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

#include <stdexcept>

namespace pgl
{
  class Timeout
  {
  public:
    Timeout(unsigned int usec)
      : _usec_timeout(usec)
    {
      if (clock_gettime(CLOCK_MONOTONIC, &_ts_start) != 0) {
	throw std::runtime_error("clock_gettime failed");
      }
    }

    operator bool() const
    {
      struct timespec ts_now;

      if (clock_gettime(CLOCK_MONOTONIC, &ts_now) != 0) {
	throw std::runtime_error("clock_gettime failed");
      }

      if (tsUsecDiff(ts_now, _ts_start) >= _usec_timeout) {
	return true;
      }

      return false;
    }

  protected:
    /*
     * Microsecond difference between two points in time stored in a timespec structure.
     */
    static uint64_t tsUsecDiff(const struct timespec& ts_a, const struct timespec& ts_b)
    {
      const uint64_t ns_abs_a = ts_a.tv_sec * 1000 * 1000 * 1000 + ts_a.tv_nsec;
      const uint64_t ns_abs_b = ts_b.tv_sec * 1000 * 1000 * 1000 + ts_b.tv_nsec;
      const uint64_t ns_diff = (ns_abs_a > ns_abs_b ?
				ns_abs_a - ns_abs_b : ns_abs_b - ns_abs_a);
      return ns_diff / 1000;
    }

  private:
    unsigned int _usec_timeout;
    struct timespec _ts_start;
  };
} /* namespace pgl */
