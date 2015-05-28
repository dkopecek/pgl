#pragma once

namespace pgl
{
  class MessageBusError
  {
  public:
    enum Code {
      TimeoutRecv,
      TimeoutSend,
      MessageInvalid,
      LimitExceeded
    };

    MessageBusError(pid_t pid, Code code, const std::string& message)
      : _pid(pid),
	_code(code),
	_message(message)
    {
    }
    pid_t pid() const
    {
      return _pid;
    }
    Code code() const
    {
      return _code;
    }
    const std::string& message() const
    {
      return _message;
    }
  private:
    const pid_t _pid; /**< who caused the error */
    const Code _code;
    const std::string _message;
  };

  class ProcessError
  {
  public:
    ProcessError(pid_t pid, int code, const std::string& message = "")
      : _pid(pid),
	_code(code),
	_message(message)
    {
    }
    pid_t pid() const
    {
      return _pid;
    }
    int code() const
    {
      return _code;
    }
    const std::string& message() const
    {
      return _message;
    }
  private:
    const pid_t _pid;
    const int _code;
    const std::string _message;
  };
} /* namespace pgl */
