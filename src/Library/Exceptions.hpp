#pragma once
#include <stdexcept>
#include <errno>

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

      const char *what() const
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

      const char *what() const
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
#define PGL_PP_CONCAT(a,b) OSCAP_CONCAT1(a,b)
#define PGL_PP_GSYM(s) PGL_PP_CONCAT(___G_, s)

#define PGL_PROTECT_ERRNO \
          for (int PGL_PP_CONCAT(__e,__LINE__)=errno,\
              PGL_PP_CONCAT(__s,__LINE__)=1;\
              PGL_PP_CONCAT(__s,__LINE__)--;\
              errno=PGL_PP_CONCAT(__e,__LINE__))

#define PGL_BUG(text) std::runtime_error("BUG: " \
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

      const char *what() const
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
