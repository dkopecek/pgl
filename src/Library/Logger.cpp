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
#include "Logger.hpp"
#include "Exceptions.hpp"
#include <sys/types.h>
#include <unistd.h>

namespace pgl
{
  /* Instantiate the logger */
  Logger G_logger;

  LogStream::LogStream(Logger& logger, const std::string& file, int line,
      const std::string& function)
    : _logger(logger), _file(file), _line(line), _function(function)
  {
  }

  LogStream::LogStream(const LogStream& rhs)
    : _logger(rhs._logger), _file(rhs._file), _line(rhs._line),
    _function(rhs._function)
  {
  }

  LogStream::~LogStream()
  {
    _logger.write(_file, _line, _function, str());
  }

  Logger::Logger()
  {
    const char * const envval = getenv("PGL_DEBUG");
    _enabled = false;
    /*
     * If PGL_DEBUG=1 is set in the current environment, then
     * open the log file stream and mark the logger as active.
     */
    if (envval != nullptr && strcmp(envval, "1") == 0) {
      _path = "pgl-debug.";
      _path += std::to_string(getpid());
      _path += ".log";
      _stream.open(_path);
      _enabled = true;
    }
  }

  Logger::~Logger()
  {
    if (isEnabled()) {
      _stream.close();
      _enabled = false;
    }
  }

  bool Logger::isEnabled() const
  {
    return _enabled;
  }

  LogStream Logger::operator()(const std::string& file, const int line,
      const std::string& function)
  {
    return LogStream(*this, file, line, function);
  }

  void Logger::write(const std::string& file, int line, const std::string& func,
      const std::string& message)
  {
    std::unique_lock<std::mutex> lock(_mutex);

    _stream << timestamp() << " "
      << file << " "
      << line << " "
      << func << " "
      << ": " << message << std::endl;

    return;
  }

  /*
   * Generate a timestamp string in the form:
   * <seconds>.<microseconds>
   */
  const std::string Logger::timestamp()
  {
    struct timeval tv_now = { 0, 0 };

    if (gettimeofday(&tv_now, nullptr) != 0) {
      throw SyscallError("gettimeofday", errno, /*nolog=*/true);
    }

    return std::to_string(tv_now.tv_sec) \
      + "." + std::to_string(tv_now.tv_usec);
  }

} /* namespace pgl */

