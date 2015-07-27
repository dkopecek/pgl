#pragma once
#include <stdexcept>

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

  //

} /* namespace pgl */
