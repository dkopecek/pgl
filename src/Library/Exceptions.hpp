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
#include <stdexcept>
#include <errno.h>

namespace pgl
{
  class Exception : public std::exception
  {
  };

  /**
   * Message Bus Exception class.
   *
   * Methods that interact with the message bus throw this
   * exception type when they cannot continue operating as
   * expected.
   *
   * Methods that throw this exception set the `recoverable'
   * flag to indicate that calling the method again is
   * possible and might result in completion of the requested
   * operation.
   */
  class BusError : public Exception
  {
    public:
      BusError(bool recoverable)
      {
        setRecoverable(recoverable);
      }

      const char *what() const noexcept
      {
        return "pgl::BusError";
      }

      bool isRecoverable() const
      {
        return _recoverable;
      }

      void setRecoverable(bool recoverable)
      {
        _recoverable = recoverable;
        return;
      }
    private:
      bool _recoverable;
  };

  /**
   * System Call Failure Exception class
   *
   * Methods that use system calls to perform certain kinds
   * of operation throw this exception if a system call fails.
   *
   * The name of the system (*libc) call and the  errno value
   * after the system call is stored in the exception
   *
   */
  class SyscallError : public Exception
  {
    public:
      SyscallError(const std::string& syscall, int error)
        : _syscall(syscall), _error(error)
      {
      }

      const char *what() const noexcept
      {
        return "pgl::SyscallError";
      }

      const std::string& syscall() const
      {
        return _syscall;
      }

      int error() const
      {
        return _error;
      }
    private:
      const std::string _syscall;
      const int _error;
  };

#define PGL_PP_CONCAT1(a,b) a ## b
#define PGL_PP_CONCAT(a,b) PGL_PP_CONCAT1(a,b)
#define PGL_PP_GSYM(s) PGL_PP_CONCAT(___G_, s)

#define PGL_PROTECT_ERRNO \
          for (int PGL_PP_CONCAT(__e,__LINE__)=errno,\
              PGL_PP_CONCAT(__s,__LINE__)=1;\
              PGL_PP_CONCAT(__s,__LINE__)--;\
              errno=PGL_PP_CONCAT(__e,__LINE__))

#define PGL_BUG(text) std::runtime_error(std::string("BUG: ") \
    + "[" + __FILE__ + "@" + std::to_string(__LINE__) + "] "\
    + __PRETTY_FUNCTION__\
    + ": " + text)\

  /**
   * API Usage Error Exception class.
   *
   * Thrown when an API function is used in a wrong way. Explanatory message
   * is stored in the exception.
   */
  class APIError : public Exception
  {
    public:
      APIError(const std::string& api_name, const std::string& message)
        : _api_name(api_name), _message(message)
      {
      }

      const char *what() const noexcept
      {
        return "pgl::APIError";
      }

      const std::string& name() const
      {
        return _api_name;
      }

      const std::string& message() const
      {
        return _message;
      }
    private:
      const std::string _api_name;
      const std::string _message;
  };

#define PGL_API_ERROR(message) APIError(__PRETTY_FUNCTION__, message)

} /* namespace pgl */
