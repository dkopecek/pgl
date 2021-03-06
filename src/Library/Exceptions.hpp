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
#include "Logger.hpp"
#include <stdexcept>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

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
      BusError(bool recoverable, pid_t pid = -1)
      {
        setRecoverable(recoverable);
        setPID(-1);
        try {
          PGL_LOG() << "BusError: pid=" << getPID()
            << ", recoverable=" << recoverable;
        } catch(...) {
        }
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

      void setPID(pid_t pid)
      {
        _pid = pid;
        return;
      }

      pid_t getPID() const
      {
        return _pid;
      }

    private:
      bool _recoverable;
      pid_t _pid;
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
      SyscallError(const std::string& syscall, int error, bool nolog = false)
        : _syscall(syscall), _error(error)
      {
        if (!nolog) {
          try {
            PGL_LOG() << "SyscallError: " << syscall << ": errno=" << errno;
          } catch(...) {
          }
        }
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
    + "[" + PGL_SOURCE_FILE + "@" + std::to_string(__LINE__) + "] "\
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
        try {
          PGL_LOG() << "APIError: " << api_name << ": " << message;
        } catch(...) {
        }
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
