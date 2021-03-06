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
#include "Process.hpp"
#include "Exceptions.hpp"
#include "Message.hpp"
#include "Timeout.hpp"
#include "Utility.hpp"
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/socket.h>

namespace pgl
{
  Process::Process()
    : _rnd_hashbyte(0, 31)
  {
    _pid = -1;
    _pid_master = -1;
    _bus_wfd = -1;
    _bus_rfd = -1;
    _state = Process::State::Initialized;
    _keep_env = { "SSH_AUTH_SOCK", "GPG_AGENT_INFO", "PGL_DEBUG" };
    _closeall_fds = 1;
    for (unsigned int i = 0; i < Message::type_count; ++i) {
      _bus_recv_queued[i] = false;
    }
    _bus_send_timeout_usec = 10 * 1000 * 1000;
    _bus_recv_timeout_usec = 10 * 1000 * 1000;
    _pgl_signal_handling = true;
    _signal_fd = -1;
  }

  Process::~Process()
  {
    _bus_wfd = -1;
    _bus_rfd = -1;
    _state = Process::State::Invalid;
  }

  const std::string& Process::getName() const
  {
    return _name;
  }

  void Process::setName(const std::string& name)
  {
    _name = name;
    return;
  }

  void Process::setPID(const pid_t pid)
  {
    // TODO: Check state
    _pid = pid;
    return;
  }

  pid_t Process::getPID() const
  {
    return _pid;
  }

  void Process::setState(Process::State state)
  {
    // TODO: apply state changes
    _state = state;
    return;
  }

  Process::State Process::getState() const
  {
    return _state;
  }

  void Process::setExecPath(const std::string& exec_path)
  {
    _exec_path = exec_path;
    _exec_name = pathBasename(_exec_path) + "/" + _name;
    return;
  }

  const std::string& Process::getExecPath() const
  {
    return _exec_path;
  }

  void Process::setMessageBusFDs(int rfd, int wfd)
  {
    _bus_rfd = rfd;
    _bus_wfd = wfd;
    return;
  }

  void Process::getMessageBusFDs(int *rfd_ptr, int *wfd_ptr) const
  {
    if (rfd_ptr) {
      *rfd_ptr = _bus_rfd;
    }
    if (wfd_ptr) {
      *wfd_ptr = _bus_wfd;
    }
    return;
  }

  void Process::setSignalFD(int fd)
  {
    _signal_fd = fd;
    return;
  }

  int Process::getSignalFD() const
  {
    return _signal_fd;
  }

  void Process::setMessageBusSendTimeout(unsigned int usec)
  {
    _bus_send_timeout_usec = usec;
    return;
  }

  unsigned int Process::getMessageBusSendTimeout() const
  {
    return _bus_send_timeout_usec;
  }

  void Process::setMessageBusRecvTimeout(unsigned int usec)
  {
    _bus_recv_timeout_usec = usec;
    return;
  }

  unsigned int Process::getMessageBusRecvTimeout() const
  {
    return _bus_recv_timeout_usec;
  }

  void Process::processSignals()
  {
    if (!_pgl_signal_handling) {
      return;
    }
    try {
      struct signalfd_siginfo ssi;

      if (read(_signal_fd, &ssi, sizeof ssi) != sizeof ssi) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
          return;
        }
        throw SyscallError("read(_signal_fd)", errno);
      }

      signalHandler(ssi);
    }
    catch(...) {
      PGL_LOG() << "An exception occured during signal processing. Terminating.";
      setProcessTerminate(255);
    }
  }

  void Process::setSignalHandling(bool enabled)
  {
    _pgl_signal_handling = enabled;
    return;
  }

  void Process::signalHandler(const struct signalfd_siginfo& ssi)
  {
    PGL_LOG() << "Default signal handler called for signal #" << ssi.ssi_signo;

    switch (ssi.ssi_signo) {
      case SIGTERM:
      case SIGINT:
      case SIGQUIT:
        setProcessTerminate(EXIT_SUCCESS);
        break;
    }

    return;
  }

  /*
   * Method called right before calling exec(3)
   * to start the process from it's master/parent
   * process
   */
  void Process::preExecSetup()
  {
    return;
  }

  /*
   * Method called inside the newly created process
   * right before entering the process main loop.
   */
  void Process::postExecSetup()
  {
    return;
  }

  /*
   * Resolve a process name to it's current PID.
   *
   * Returns -1 of the name couldn't be resolved.
   */
  pid_t Process::messageBusResolve(const std::string& name)
  {
    Message request(name.size());

    request.setFrom(getPID());
    request.setTo(0);
    request.setType(Message::Type::BUS_PID_LOOKUP);
    request.copyToData(name);

    const Message reply = std::move(messageBusSendRecv(request, Message::Type::BUS_PID_LOOKUP));
    pid_t pid = -1;
    reply.copyFromData(pid);

    return pid;
  }

  int Process::messageBusWait(unsigned int max_wait_usec)
  {
    int nfds = -1;
    int fd = -1;
    struct timeval tv_timeout = { 0, max_wait_usec };
    fd_set rd_set;

    getMessageBusFDs(&fd, nullptr);

    do {
      FD_ZERO(&rd_set);
      FD_SET(fd, &rd_set);
      FD_SET(getSignalFD(), &rd_set);

      nfds = select(std::max(fd, getSignalFD()) + 1,
          &rd_set, nullptr, nullptr,
          max_wait_usec > 0 ? &tv_timeout : nullptr);

      if (nfds < 0) {
        return -1;
      }
      if (nfds > 0 && FD_ISSET(getSignalFD(), &rd_set)) {
        processSignals();
        --nfds;
      }
      if (nfds == 1 && FD_ISSET(fd, &rd_set)) {
        break;
      }
    } while(nfds != 0);

    return nfds;
  }

  void Process::messageBusSend(pid_t peer_pid, const std::string& message)
  {
    Message msg(message.size());
    msg.setFrom(getPID());
    msg.setTo(peer_pid);
    msg.setType(Message::Type::M2M);
    msg.copyToData(message);
    messageBusSend(msg);
    return;
  }

  pid_t Process::messageBusRecv(pid_t peer_pid, std::string& message)
  {
    const Message msg = std::move(messageBusRecvMessage(Message::Type::M2M));
    msg.copyFromData(message);
    return msg.getFrom();
  }

  pid_t Process::messageBusSendRecv(pid_t peer_pid, const std::string& message, std::string& reply_message)
  {
    Message request(message.size());

    request.setFrom(getPID());
    request.setTo(peer_pid);
    request.setType(Message::Type::M2M);
    request.copyToData(message);

    const Message reply = std::move(messageBusSendRecv(request, Message::Type::M2M));
    reply.copyFromData(reply_message);

    return reply.getFrom();
  }

  void Process::messageBusSend(Message& msg, bool lock_bus)
  {
    std::unique_lock<std::mutex> lock_w(_bus_wfd_mutex, std::defer_lock);

    processSignals();

    if (lock_bus) {
      lock_w.lock();
    }

    msg.finalize();

    /*
     * Write the message data to the bus.
     */
    const uint8_t *buffer = msg.buffer();
    const size_t buffer_size = msg.bufferSize();

    Timeout timeout(getMessageBusSendTimeout());
    messageBusWrite(_bus_wfd, buffer, buffer_size, timeout.getRemainingTime());

    /*
     * If it's a M2M_FD message, we have to send the
     * fd using sendmsg.
     */
    if (msg.getType() == Message::M2M_FD) {
      try {
        writeFD(_bus_wfd, msg.getFD(), timeout.getRemainingTime());
      }
      catch(BusError& ex) {
        ex.setRecoverable(false);
        throw;
      }
    }

    return;
  }

  Message Process::messageBusRecvMessage(Message::Type type, bool lock_bus)
  {
    std::unique_lock<std::mutex> lock_r(_bus_rfd_mutex, std::defer_lock);

    processSignals();

    if (lock_bus) {
      lock_r.lock();
    }

    /*
     * First check whether there's a message of the requested type queued
     * in the receiving queue.
     */
    if (messageBusRecvQueued(type)) {
      return std::move(messageBusRecvDequeue(type, /*lock_bus=*/false));
    }

    /*
     * Start the timeout counter for receiving the message of the requested
     * type. If there's no message at all received, the timeout counter in
     * the messageBusRecvMessage(bool) method will trigger an exception.
     */
    Timeout timeout(getMessageBusRecvTimeout());
    do {
      Message msg = std::move(messageBusRecvMessage(/*lock_bus=*/false));
      if (msg.getType() == type) {
        return std::move(msg);
      }
      else {
        messageBusRecvEnqueue(std::move(msg));
      }
    } while(!timeout);

    throw BusError(/*recoverable=*/true); // XXX: message text?
  }

  Message Process::messageBusRecvMessage(bool lock_bus)
  {
    std::unique_lock<std::mutex> lock_r(_bus_rfd_mutex, std::defer_lock);

    if (lock_bus) {
      lock_r.lock();
    }

    /* Read message header */
    Message::Header header;
    Timeout timeout(getMessageBusRecvTimeout());
    messageBusRead(_bus_rfd, reinterpret_cast<uint8_t *>(&header),
        sizeof(Message::Header), timeout.getRemainingTime());

    /* Check reply_header.size value */
    Message msg(header);
    try {
      messageBusRead(_bus_rfd, msg.dataWritable(), msg.dataSize(),
          timeout.getRemainingTime());
    }
    catch(BusError& ex) {
      ex.setRecoverable(false);
      throw;
    }

    /*
     * Problem: cannot trust the data until validated
     * but cannot validate until the fd is received.
     */
    if (msg.getTypeUnsafe() == Message::Type::M2M_FD) {
      try {
        const int fd = readFD(_bus_rfd, timeout.getRemainingTime());
        msg.setFDUnsafe(fd);
      }
      catch (BusError& ex) {
        ex.setRecoverable(false);
        throw;
      }
    }

    /* Check sanity of the whole message */
    msg.validate();

    return std::move(msg);
  }

  Message Process::messageBusSendRecv(Message& msg, Message::Type recv_type)
  {
    std::unique_lock<std::mutex> lock_w(_bus_wfd_mutex);
    std::unique_lock<std::mutex> lock_r(_bus_rfd_mutex);

    messageBusSend(msg, /*lock_bus=*/false);
    return std::move(messageBusRecvMessage(recv_type, /*lock_bus=*/false));
  }

  void Process::messageBusSendFD(pid_t peer_pid, int fd, const std::string& message)
  {
    Message msg(message.size());
    msg.setFrom(getPID());
    msg.setTo(peer_pid);
    msg.setFD(fd);
    msg.setType(Message::Type::M2M_FD);
    msg.copyToData(message);
    messageBusSend(msg);
    return;
  }

  pid_t Process::messageBusRecvFD(pid_t peer_pid, int *fd, std::string *message)
  {
    if (fd == nullptr) {
      throw std::invalid_argument("BUG: messageBusRecvFD: fd == nullptr");
    }

    Message msg = std::move(messageBusRecvMessage(Message::Type::M2M_FD));

    if (msg.getFrom() != peer_pid) {
      messageBusRecvEnqueue(std::move(msg));
      return (pid_t)-1;
    }

    *fd = msg.getFD();

    if (message != nullptr) {
      msg.copyFromData(*message);
    }

    return msg.getFrom();
  }

  // NOTE: Add a sanity field. 
  //
  // Sanity field serves for the receiving side to know
  // whether the source side still operates as expected
  // (i.e. it's not sending random garbage that doesn't
  //  make sense)
  //
  // When sending a message, the sending side has to
  // compute a hash value, and include a random byte from
  // that hash in the message. The position of the selected
  // byte is also included. The receiving side checks
  // correctness of the hash byte at the selected position
  // and that the position is selected randomly by the
  // sending side.
  //
  // IDEA: Seed random number generator of byte position
  //       selector on both sides from PID of the child
  //       or from a token passed to the child via an
  //       environment variable

  pid_t Process::spawn(int argc, char * argv[])
  {
    int bus_fd[2];

    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, bus_fd) != 0) {
      throw SyscallError("socketpair(AF_LOCAL, SOCK_STREAM)", errno);
    }

    if (fcntl(bus_fd[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(bus_fd[1], F_SETFL, O_NONBLOCK) != 0) {
      throw SyscallError("fcntl(fd, F_SETFL, O_NONBLOCK)", errno);
    }

    setMessageBusFDs(/*rfd=*/bus_fd[0], /*wfd=*/bus_fd[0]);

    /*-============= FORK  ===============- */
    const pid_t pid = fork();

    if (pid == 0) {
      /* Child */
      ::close(bus_fd[0]);
      ::close(STDIN_FILENO);
      ::close(STDOUT_FILENO);
      ::close(STDERR_FILENO);

      const int null_fd = open("/dev/null", O_RDONLY);
      if (null_fd == -1) {
        throw SyscallError("open(/dev/null, O_RDONLY)", errno);
      }

      if (::dup2(null_fd, STDERR_FILENO) == -1) {
        PGL_PROTECT_ERRNO {
          ::close(null_fd);
        }
        throw SyscallError("dup2", errno);
      }

      if (::dup2(null_fd, STDIN_FILENO) == -1 ||
          ::dup2(null_fd, STDOUT_FILENO) == -1) {
        PGL_PROTECT_ERRNO {
          ::close(bus_fd[1]);
          ::close(null_fd);
        }
        throw SyscallError("dup2", errno);
      }

      setMessageBusFDs(/*rfd=*/bus_fd[1], /*wfd=*/bus_fd[1]);

      if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
        ::close(bus_fd[1]);
        ::close(null_fd);
        throw SyscallError("prctl(PR_SET_PDEATHSIG)", errno);
      }

      sigset_t mask;
      sigfillset(&mask);
      sigdelset(&mask, SIGABRT);
      sigdelset(&mask, SIGSEGV);
      sigdelset(&mask, SIGILL);
      sigdelset(&mask, SIGFPE);
      sigdelset(&mask, SIGBUS);

      const int signal_fd = signalfd(-1, &mask, SFD_NONBLOCK);
      if (signal_fd < 0) {
        throw SyscallError("signalfd", errno);
      }

      setSignalFD(signal_fd);

      char **exec_env = nullptr;
      prepareMemberEnvVariables(exec_env);

      if (exec_env == nullptr) {
        throw PGL_API_ERROR("invalid argument: exec_env == nullptr");
      }

      if (_closeall_fds > 0) {
        const int highest_open_fd = std::max(signal_fd, bus_fd[1]);
        closeAllFDs(/*from_fd=*/highest_open_fd + _closeall_fds);
      }

      preExecSetup();
      ::execvpe(_exec_path.c_str(), argv, exec_env);
      throw SyscallError("execvpe", errno);
    }
    else if (pid == -1) {
      /* fork() failure */
      throw SyscallError("fork", errno);
    }
    /*-============= FORK  ===============- */

    ::close(bus_fd[1]);

    return pid;
  }

  void Process::prepareMemberEnvVariables(char **& env_array)
  {
    /*
     * Allocate memory for the array. The maximum number of
     * items is the number of environment variables to keep
     * from the master process environment plus the PGL_EXEC_NAME,
     * PGL_BUS_WFD, PGL_BUS_RFD, PGL_SIGNAL_FD, variables plus
     * an item for the nullptr (therefore +5).
     */
    const size_t env_count_max = _keep_env.size() + 5;
    env_array = new char *[env_count_max];

    std::string exec_name_var;
    exec_name_var = "PGL_EXEC_NAME=";
    exec_name_var += getName();
    env_array[0] = strdup(exec_name_var.c_str());

    int bus_wfd = -1, bus_rfd = -1;
    getMessageBusFDs(&bus_wfd, &bus_rfd);

    std::string bus_wfd_var;
    bus_wfd_var = "PGL_BUS_WFD=";
    bus_wfd_var += std::to_string(bus_wfd);
    env_array[1] = strdup(bus_wfd_var.c_str());

    std::string bus_rfd_var;
    bus_rfd_var = "PGL_BUS_RFD=";
    bus_rfd_var += std::to_string(bus_rfd);
    env_array[2] = strdup(bus_rfd_var.c_str());

    std::string signal_fd_var;
    signal_fd_var = "PGL_SIGNAL_FD=";
    signal_fd_var += std::to_string(getSignalFD());
    env_array[3] = strdup(signal_fd_var.c_str());

    size_t env_index = 4;
    for (auto const& name : _keep_env) {
      const char * const val = getenv(name.c_str());
      if (val == nullptr) {
        continue;
      }
      std::string var = name + "=" + val;
      env_array[env_index] = strdup(var.c_str());
      ++env_index;
    }
    env_array[env_index] = nullptr;

    return;
  }

  const std::string Process::pathBasename(const std::string& path)
  {
    const std::string directory_separators = "/";
    const size_t separator_pos = path.find_last_of(directory_separators);

    if (separator_pos == std::string::npos) {
      return path;
    }
    else {
      return path.substr(separator_pos + 1);
    }
  }

  void Process::stop()
  {
    terminate(SIGTERM);
  }

  void Process::kill()
  {
    terminate(SIGKILL);
  }

  bool Process::processTerminate()
  {
    processSignals();
    return _process_terminate;
  }

  int Process::processTerminateCode() const
  {
    return _process_terminate_code;
  }

  void Process::messageBusWrite(int fd, const uint8_t *data, size_t size, unsigned int max_delay_usec)
  {
    Timeout timeout(max_delay_usec);
    size_t size_written = 0;

    while (size_written < size) {
      const ssize_t size_write = write(fd, data, size);

      if (size_write < 0) {
        /*
         * Error. Check whether it's only a temporary
         * and if we have time for another try.
         */
        if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
          if (timeout) {
            throw BusError(/*recoverable=*/true);
          }
          else {
            /*
             * There's still time, try to write again. Sleep for 1/1000 of the
             * maximum delay specified.
             */
            const struct timespec ts_sleep = { 0, max_delay_usec };
            nanosleep(&ts_sleep, nullptr);
            continue;
          }
        }
        else {
          throw SyscallError("write", errno);
        }
      }
      else {
        /*
         * At least one byte was written, update data
         * pointer and size for next write...
         */
        size_written += size_write;
        size -= size_write;
        data += size_write;
      }
    } /* while loop */

    return;
  }

  void Process::messageBusRead(int fd, uint8_t *data, size_t size, unsigned int max_delay_usec)
  {
    Timeout timeout(max_delay_usec);
    size_t size_stored = 0;

    while (size_stored < size) {
      const ssize_t size_read = read(fd, data, size);

      if (size_read < 0) {
        /*
         * Error. Check whether it's only a temporary
         * and if we have time for another try.
         */
        if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
          if (timeout) {
            throw BusError(/*recoverable=*/true);
          }
          else {
            /* There's still time, try to read again */
            const struct timespec ts_sleep = { 0, max_delay_usec };
            nanosleep(&ts_sleep, nullptr);
            continue;
          }
        }
        else {
          throw SyscallError("read", errno);
        }
      }
      else if (size_read == 0) {
        throw BusError(/*recoverable=*/false);
      }
      else {
        /*
         * At least one byte was written, update data
         * pointer and size for next write...
         */
        size_stored += size_read;
        size -= size_read;
        data += size_read;
      }
    } /* while loop */

    return;
  }

  void Process::terminate(int signal)
  {
    const pid_t pid = getPID();

    /* Check whether we consider the process as running */
    if (getState() != Process::State::Running || pid == -1) {
      return;
    }
    /* Check whether the process is acually running on the system */
    if (::kill(pid, 0) != 0) {
      setState(Process::State::Terminated);
      setPID(-1);
      return;
    }
    /* Send a termination request */
    if (::kill(pid, signal) != 0) {
      throw SyscallError("kill", errno);
    }
    /* Wait for the child to exit */
    const int waitpid_timeout_usec = 1000 * 1000;
    Timeout timeout(waitpid_timeout_usec);

    while (!timeout) {
      int pid_status = -1;
      const pid_t waitpid_ret = ::waitpid(pid, &pid_status, WNOHANG);

      if (waitpid_ret == pid) {
        return;
      }
      else if (waitpid_ret == -1) {
        throw SyscallError("waitpid", errno);
      }
      else if (waitpid_ret == 0) {
        const struct timespec ts_sleep = { 0, waitpid_timeout_usec };
        nanosleep(&ts_sleep, nullptr);
        continue;
      }
      else {
        throw PGL_BUG("unhandled waitpid() return value");
      }
    }
    throw SyscallError("waitpid", ETIMEDOUT);
  }

  uint8_t Process::expectedMessageHashBytePosition()
  {
    return _rnd_hashbyte(_rng_hashbyte);
  }

  uint8_t Process::messageHashByteAt(size_t pos, const Message::Header* header, const uint8_t *data, size_t size)
  {
    return (uint8_t)pos;
  }

  void Process::messageBusRecvEnqueue(Message&& msg)
  {
    switch(msg.getType()) {
    case Message::Type::M2M:
    case Message::Type::M2M_FD:
    case Message::Type::BUS_PID_LOOKUP:
    case Message::Type::BUS_PID_FORGET:
    case Message::Type::BUS_HEARTBEAT:
      break;
    default:
      throw std::invalid_argument("BUG: messageBusRecvEnqueue: unhandled message type");
    }
    const unsigned int n = (unsigned int)msg.getType() % Message::type_count;
    std::unique_lock<std::mutex> bus_lock(_bus_rfd_mutex);
    _bus_recv_queue[n].emplace(std::move(msg));
    _bus_recv_queued[n] = true;
    return;
  }

  Message Process::messageBusRecvDequeue(Message::Type type, bool lock_bus)
  {
    std::unique_lock<std::mutex> bus_lock(_bus_rfd_mutex, std::defer_lock);
    const unsigned int n = (unsigned int)type % Message::type_count;

    if (lock_bus) {
      bus_lock.lock();
    }

    if (_bus_recv_queue[n].empty()) {
      throw PGL_API_ERROR("cannot dequeue from an empty queue");
    }

    Message msg = std::move(_bus_recv_queue[n].front());
    _bus_recv_queue[n].pop();

    if (_bus_recv_queue[n].empty()) {
      _bus_recv_queued[n] = false;
    }

    return std::move(msg);
  }

  bool Process::messageBusRecvQueued(Message::Type type) const
  {
    const unsigned int n = (unsigned int)type % Message::type_count;
    return _bus_recv_queued[n];
  }

  void Process::setProcessTerminate(int code)
  {
    _process_terminate = true;
    _process_terminate_code = code;
    return;
  }

} /* namespace pgl */
