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
#include <mutex>
#include <fstream>
#include <sstream>
#include <sys/time.h>

namespace pgl
{
  class Logger;

  class LogStream : public std::ostringstream
  {
    public:
      LogStream(Logger& logger, const std::string& file, int line,
          const std::string& function);
      LogStream(const LogStream& rhs);
      ~LogStream();

    private:
      Logger& _logger;
      const std::string& _file;
      const int _line;
      const std::string& _function;
  };

  class Logger
  {
    public:
      Logger();
      ~Logger();

      bool isEnabled() const;

      LogStream operator()(const std::string& file, const int line,
          const std::string& function);

      void write(const std::string& file, int line, const std::string& func,
          const std::string& message);

      /*
       * Generate a timestamp string in the form:
       * <seconds>.<microseconds>
       */
      static const std::string timestamp();

    private:
      bool _enabled;
      std::string _path;
      std::mutex _mutex;
      std::ofstream _stream;
  };

  extern Logger G_logger;

#define PGL_LOG() \
  if (pgl::G_logger.isEnabled()) \
  pgl::G_logger(__FILE__, __LINE__, __PRETTY_FUNCTION__)

} /* namespace pgl */
