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
#include "Group.hpp"
#include "Exceptions.hpp"
#include "Process.hpp"
#include "Utility.hpp"
#include "Logger.hpp"
#include <sys/signalfd.h>
#include <assert.h>
#include <time.h>
#include <memory>

namespace pgl
{
  /////
  //
  // pgl::Group method definitions
  //
  /////

  Group::Group(int argc, char *argv[])
    : _process_argc(argc),
      _process_argv(argv),
      _graceful_termination_timeout(2 * 1000 * 1000)
  {
    if (argc < 1 || argv == nullptr) {
      throw std::invalid_argument("BUG: Group ctor: invalid argc/argv[] parameter values");
    }
    if (argv[0] == nullptr) {
      throw std::invalid_argument("BUG: Group ctor: argv[0] == nullptr");
    }

    //
    // Find out the process mode from the exectable path
    // and argv[0] value
    //
    char path_buffer[PATH_MAX];
    const ssize_t path_length = ::readlink("/proc/self/exe",
        path_buffer, sizeof path_buffer);

    if (path_length == -1) {
      throw SyscallError("readlink", errno);
    }

    const std::string exec_path(path_buffer, path_length);
    const char * exec_name_env = getenv("PGL_EXEC_NAME");
    const char * bus_rfd_env = getenv("PGL_BUS_RFD");
    const char * bus_wfd_env = getenv("PGL_BUS_WFD");
    const char * signal_fd_env = getenv("PGL_SIGNAL_FD");
    bool master_mode;
    std::string exec_name;

    if (exec_name_env == nullptr) {
      exec_name = Process::pathBasename(exec_path);
      master_mode = true;
    }
    else {
      exec_name = exec_name_env;
      master_mode = false;
    }

    _exec_path = exec_path;
    _exec_name = exec_name;
    _group_terminate = false;
    _group_exit_code = EXIT_SUCCESS;

    if (master_mode) {
      _master_mode = true;
      _member_instantiated = false;

      sigset_t mask;
      sigfillset(&mask);
      sigdelset(&mask, SIGABRT);
      sigdelset(&mask, SIGSEGV);
      sigdelset(&mask, SIGILL);
      sigdelset(&mask, SIGFPE);
      sigdelset(&mask, SIGBUS);

      if (sigprocmask(SIG_SETMASK, &mask, nullptr) != 0) {
        throw SyscallError("sigprocmask", errno);
      }
      if ((_signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC)) == -1) {
        throw SyscallError("signalfd", errno);
      }
    }
    else {
      _master_mode = false;
      _member_instantiated = false;
      _requested_name = exec_name;

      if (bus_rfd_env == nullptr || bus_wfd_env == nullptr) {
        throw std::invalid_argument("BUG: PGL_BUS_WFD and/or PGL_BUS_RFD environment variables not set");
      }
      _member_bus_wfd = std::stoi(bus_wfd_env);
      _member_bus_rfd = std::stoi(bus_rfd_env);

      PGL_LOG() << "Set member bus fds to wfd=" << _member_bus_wfd
        << " rfd=" << _member_bus_rfd;

      if (signal_fd_env == nullptr) {
        throw std::invalid_argument("BUG: PGL_SIGNAL_FD environment variable not set");
      }
     _signal_fd = std::stoi(signal_fd_env);
     PGL_LOG() << "Set member signal fd to " << _signal_fd;
    }

    /*
     * Default task timeouts: 5 seconds.
     */
    _task_send_timeout_usec = 5 * 1000 * 1000;
    _task_recv_timeout_usec = 5 * 1000 * 1000;

    /*
     * Default message size limit (bytes).
     */
    _message_size_limit = 1* 1024 * 1024;

    return;
  }

  void Group::setTaskSendTimeout(unsigned int usec)
  {
    _task_send_timeout_usec = usec;
    return;
  }

  unsigned int Group::getTaskSendTimeout() const
  {
    return _task_send_timeout_usec;
  }

  void Group::setTaskRecvTimeout(unsigned int usec)
  {
    _task_recv_timeout_usec = usec;
    return;
  }

  unsigned int Group::getTaskRecvTimeout() const
  {
    return _task_recv_timeout_usec;
  }


  void Group::setMessageSizeLimit(size_t bytes)
  {
    _message_size_limit = bytes;
    return;
  }

  size_t Group::getMessageSizeLimit() const
  {
    return _message_size_limit;
  }

  int Group::run()
  {
    if (_master_mode) {
      return masterRun();
    }
    else {
      return memberRun();
    }
  }

  int Group::masterRun()
  {
    masterStartProcesses();
    masterMainloop();
    masterStopProcesses();
    return masterGetExitCode();
  }

  void Group::masterStartProcesses()
  {
    try {
      std::unique_lock<std::mutex> map_lock(_process_map_mutex);
      for (auto& process_entry : _process_by_name) {
        auto process = process_entry.second;
        pid_t pid = process->spawn(_process_argc, _process_argv);
        process->setPID(pid);
        _process_by_pid[pid] = process;
      }
    }
    catch(const std::exception& ex) {
      masterStopProcesses();
    }
  }

  void Group::masterStopProcesses()
  {
    std::unique_lock<std::mutex> map_lock(_process_map_mutex);
    for (auto& process_entry : _process_by_pid) {
      auto process = process_entry.second;
      try {
        process->stop();
      } catch(const std::exception& ex) {
        process->kill();
      }
    }
  }

  bool Group::masterMainloopTerminated() const
  {
    if (_group_terminate) {
      /*
       * Check whether the graceful termination period
       * is over. Return immediatelly if there's no more
       * time left to complete queued tasks.
       */
      if (_graceful_termination_timeout) {
        PGL_LOG() << "Graceful exit timeout expired! "
          << "Returning from main loop." << std::endl;
        return true;
      }
      /*
       * We can exit the main loop if the task queues are
       * empty.
       */
      if (_tasks_wr.empty() && _tasks_rd.empty()) {
        PGL_LOG() << "Task queues are empty. "
          << "Returning from main loop." << std::endl;
        return true;
      }
    }

    return false;
  }

  void Group::masterMainloopCollectActiveFDs(fd_set& rd_set, fd_set& wr_set,
      int& max_fd, int& max_rfd)
  {
    FD_SET(_signal_fd, &rd_set);
    max_fd = _signal_fd;

    for (auto const& map_entry : _process_by_pid) {
      auto const& process = map_entry.second;
      int fd = -1;
      process->getMessageBusFDs(&fd, nullptr);
      if (fd == -1) {
        throw PGL_BUG("getMessageBusFDs method returned an invalid fd");
      }

      max_fd = std::max(max_fd, fd);
      max_rfd = std::max(max_rfd, fd);

      FD_SET(fd, &rd_set);
    }

    for (auto const& map_entry : _tasks_wr) {
      auto const& queue = map_entry.second;
      if (queue.size() > 0) {
        const int fd = map_entry.first;
        max_fd = std::max(max_fd, fd);
        FD_SET(fd, &wr_set);
      }
    }

    return;
  }

  int Group::masterMainloopWaitForEvents(fd_set& rd_set, fd_set& wr_set, int max_fd)
  {
    struct timeval tv_timeout = { 10, 0 /*us*/ };

    const int nfds = select(max_fd + 1, &rd_set, &wr_set, nullptr, &tv_timeout);

    if (nfds == -1) {
      PGL_PROTECT_ERRNO {
        PGL_LOG() << "select returned -1: errno=" << errno;
      }
      throw SyscallError("select", errno);
    }
    else if (nfds == 0) {
      PGL_LOG() << "select timeout:"
        << " active fds (rd)= " << _tasks_rd.size()
        << " active fds (wr)= " << _tasks_wr.size();
    }

    return nfds;
  }

  void Group::masterMainloopProcessWriteEvents(fd_set& wr_set)
  {
    /*
     * Handle writes before reads to free some memory
     */
    for (auto it = _tasks_wr.begin(); it != _tasks_wr.end(); ) {
      const int fd = it->first;

      if (FD_ISSET(fd, &wr_set)) {
        FD_CLR(fd, &wr_set);
        auto& queue = it->second;

        if (queue.empty()) {
          PGL_LOG() << "BUG: empty write queue for active fd=" << fd;
          it = _tasks_wr.erase(it);
          continue;
        }

        FDTask* task = queue.front();
        assert(task->fd() == fd);

        PGL_LOG() << "Running write task for fd=" << fd;

        if (task->run(*this)) {
          PGL_LOG() << "Write task for fd=" << fd << " complete, deleting.";
          queue.pop();
          delete task;
        }

        if (queue.empty()) {
          PGL_LOG() << "Removing empty write queue for fd=" << fd;
          it = _tasks_wr.erase(it);
          continue;
        }
      }

      ++it;
    } /* write task loop end */

    return;
  }

  void Group::masterMainloopProcessReadEvents(fd_set& rd_set, int max_rfd)
  {
    /* Handle reads */
    for (int fd = 0; fd <= max_rfd; ++fd) {
      if (FD_ISSET(fd, &rd_set)) {
        FD_CLR(fd, &rd_set);
        if (_tasks_rd.count(fd) == 0) {
          /* Do not create a new task if we are in the termination phase */
          if (_group_terminate) {
            PGL_LOG() << "Termination phase. Ignoring message on fd=" << fd;
            continue;
          }
          /* Create a new RecvHeaderTask */
          PGL_LOG() << "Data available on fd=" << fd << "."
            << " Trying to read message header.";
          masterReceiveHeader(fd);
        }
        else {
          /* Handle existing read task */
          auto& queue = _tasks_rd[fd];

          if (queue.empty()) {
            PGL_LOG() << "BUG: Empty read queue for active fd=" << fd;
            _tasks_rd.erase(fd);
            continue;
          }

          FDTask* task = queue.front();
          assert(task->fd() == fd);

          PGL_LOG() << "Running read task for fd=" << fd;

          if (task->run(*this)) {
            PGL_LOG() << "Read task for fd=" << fd << " complete, deleting.";
            queue.pop();
            delete task;
          }

          if (queue.empty()) {
            PGL_LOG() << "Removing empty read queue for fd=" << fd;
            _tasks_rd.erase(fd);
            continue;
          }
        }
      }
    } /* read fd loop */

    return;
 }

  void Group::masterMainloopProcessEvents(fd_set& rd_set, fd_set& wr_set, int max_rfd)
  {
    /*
     * Handle signals first
     */
    if (FD_ISSET(_signal_fd, &rd_set)) {
      PGL_LOG() << "Data available on signal fd=" << _signal_fd;
      masterReceiveSignal();
      FD_CLR(_signal_fd, &rd_set);
    }
    /*
     * Handle write and read events
     */
_restart:
    try {
      masterMainloopProcessWriteEvents(wr_set);
      masterMainloopProcessReadEvents(rd_set, max_rfd);
    }
    catch(const BusError& ex) {
      if (!ex.isRecoverable() || ex.getPID() == -1) {
        throw;
      }

      masterHandleMemberTermination(ex.getPID());

      if (masterMainloopTerminated()) {
        return;
      }

      goto _restart;
    }

    return;
  }

  void Group::masterMainloop()
  {
    PGL_LOG() << "Entering master mainloop";

    while (!masterMainloopTerminated()) {
      int max_fd = -1;
      int max_rfd = -1;
      fd_set rd_set;
      fd_set wr_set;
      FD_ZERO(&rd_set);
      FD_ZERO(&wr_set);

      masterMainloopCollectActiveFDs(rd_set, wr_set, max_fd, max_rfd);
      if (masterMainloopWaitForEvents(rd_set, wr_set, max_fd) < 1) {
        continue;
      }
      masterMainloopProcessEvents(rd_set, wr_set, max_rfd);
    }

    PGL_LOG() << "Returning from master mainloop";
    return;
  }

  void Group::masterReceiveSignal()
  {
    struct signalfd_siginfo sig;

    // NOTE: Tolerate EAGAIN, EINTR here?
    if (read(_signal_fd, &sig, sizeof sig) != sizeof sig) {
      throw SyscallError("read(_signal_fd)", errno);
    }

    PGL_LOG() << "Received signal #" << sig.ssi_signo;

    switch(sig.ssi_signo) {
      case SIGCHLD:
        masterHandleMemberTermination((pid_t)sig.ssi_pid);
        break;
      case SIGTERM:
      case SIGINT:
        /* Enter shutdown mode */
        PGL_LOG() << "Received SIGTERM/SIGINT: shutting down.";
        masterTerminate();
        break;
      default:
        PGL_LOG() << "Signal ignored.";
    }

    return;
  }

  void Group::masterHandleMemberTermination(pid_t pid)
  {
    PGL_LOG() << "Handling member termination: pid=" << pid;
    int status = -1;
    bool pid_killed = false;

    for (;;) {
      const pid_t retval = ::waitpid(pid, &status, WNOHANG);

      if (retval == pid) {
        /* jump out of the loop and process the status */
        PGL_LOG() << "got member process exit status: " << status;
        break;
      }
      else {
        PGL_LOG() << "member did not change process state yet, sending SIGKILL";
        /* the child exists, no state change yet */
        if (retval == 0 && !pid_killed) {
          /* Kill it, wait a while and try again waitpid */
          const struct timespec ts_wait = { 0, 1000 * 1000};
          ::kill(pid, SIGKILL);
          ::nanosleep(&ts_wait, nullptr);
          pid_killed = true;
        }
        else {
          throw SyscallError("waitpid", errno);
        }
      }
    }

    if (WIFEXITED(status)) {
      PGL_LOG() << "member exited with return value: " << WEXITSTATUS(status);
      masterSetExitCode(WEXITSTATUS(status));
    }
    else if(WIFSIGNALED(status)) {
      PGL_LOG() << "member was killed by signal: " << WTERMSIG(status);
    }

    switch(masterGetMemberTerminationAction(pid))
    {
      case TerminationAction::Restart:
        masterRestartMember(pid);
        break;
      case TerminationAction::Terminate:
        masterTerminate();
        break;
      default:
        throw PGL_BUG("Unknown termination action");
    }

    return;
  }

  Group::TerminationAction Group::masterGetMemberTerminationAction(pid_t pid)
  {
    return Group::TerminationAction::Terminate;
  }

  void Group::masterReceiveHeader(int fd)
  {
    PGL_LOG() << "Receiving header from fd=" << fd;
    std::unique_ptr<FDTask> task(new Group::HeaderRecvTask(fd, _task_recv_timeout_usec));

    if (!task->run(*this)) {
       /*
       * Completion of the task would block the thread, add
       * it to read tasks. It'll be completed then the fd becoms
       * readable again.
       */
      masterAddReadTask(task.release());
    }

    return;
  }

  void Group::masterRestartMember(pid_t pid)
  {
  }

  int Group::masterGetExitCode()
  {
    return _group_exit_code;
  }

  void Group::masterSetExitCode(int exit_code)
  {
    _group_exit_code = exit_code;
    return;
  }

  int Group::memberRun()
  {
    std::unique_lock<std::mutex> map_lock(_process_map_mutex);
    auto& process = _process_by_pid[::getpid()];
    process->postExecSetup();
    process->setState(Process::State::Running);
    return process->main(_process_argc, _process_argv);
  }

  void Group::masterAddReadTask(FDTask* task)
  {
    PGL_LOG() << "Adding read task";
    const int fd = task->fd();
    _tasks_rd[fd].push(task);
    return;
  }

  void Group::masterAddWriteTask(FDTask* task)
  {
    PGL_LOG() << "Adding write task";
    const int fd = task->fd();
    _tasks_wr[fd].push(task);
    return;
  }

  void Group::masterHandleBusMessage(Message&& msg, int from_fd)
  {
    PGL_LOG() << "Handling bus message on fd=" << from_fd;
    msg.validate();

    switch(msg.getType())
      {
      case Message::Type::M2M:
      case Message::Type::M2M_FD:
        masterRouteMessage(std::move(msg));
        break;
      case Message::Type::BUS_PID_LOOKUP:
        masterPIDLookupReply(std::move(msg), from_fd);
        break;
      default:
        throw std::invalid_argument("BUG: masterHandleBusMessage: unhandled message type");
      }

    return;
  }

  void Group::masterRouteMessage(Message&& msg)
  {
    const pid_t pid_to = msg.getTo();
    auto const& process = _process_by_pid[pid_to];
    int fd = -1;
    PGL_LOG() << "Routing message to PID " << pid_to;
    process->getMessageBusFDs(nullptr, &fd);
    FDTask* task = new MessageSendTask(fd, std::move(msg), _task_send_timeout_usec);
    masterAddWriteTask(task);
    return;
  }

  void Group::masterPIDLookupReply(Message&& msg, int from_fd)
  {
    PGL_LOG() << "PID lookup request on fd=" << from_fd;
    const std::string name(reinterpret_cast<const char *>(msg.data()), msg.dataSize());
    pid_t pid = -1;

    auto range = _process_by_name.equal_range(name);
    for (auto entry = range.first; entry != range.second; ++entry) {
      auto process = entry->second;
      pid = process->getPID();
      break;
    }

    PGL_LOG() << "PID lookup response: " << name << " => " << pid;

    Message reply(sizeof(pid_t));
    reply.setFrom(0);
    reply.setTo(msg.getFrom());
    reply.setType(Message::Type::BUS_PID_LOOKUP);
    reply.copyToData(&pid, sizeof (pid_t));
    reply.finalize();

    FDTask* task = new MessageSendTask(from_fd, std::move(reply), _task_send_timeout_usec);
    masterAddWriteTask(task);
    return;
  }

  void Group::masterTerminate()
  {
    _group_terminate = true;
    _graceful_termination_timeout.reset();
    return;
  }

  void Group::masterSetTerminationTimeout(unsigned int usec)
  {
    _graceful_termination_timeout.set(usec);
    return;
  }

  bool Group::inspectMessageHeader(const Message::Header& header, int fd)
  {
    /* TODO: check sender pid */
    if (header.size >= getMessageSizeLimit()) {
      return false;
    }

    return true;
  }

  /////
  //
  // pgl::Group::FDTask method definitions
  //
  /////

  Group::FDTask::FDTask(const int fd, const unsigned int usec_timeout)
    : _fd(fd),
      _timeout(usec_timeout),
      _failed(false)
  {
  }

  bool Group::FDTask::operator==(const Group::FDTask& rhs) const
  {
    return _fd == rhs._fd;
  }

  bool Group::FDTask::operator<(const Group::FDTask& rhs) const
  {
    return _fd < rhs._fd;
  }

  bool Group::FDTask::operator>(const Group::FDTask& rhs) const
  {
    return _fd > rhs._fd;
  }

  int Group::FDTask::fd() const
  {
    return _fd;
  }

  const Timeout& Group::FDTask::timeout() const
  {
    return _timeout;
  }

  bool Group::FDTask::failed() const
  {
    return _failed;
  }

  void Group::FDTask::markAsFailed()
  {
    _failed = true;
    return;
  }

  bool Group::FDTask::failTask(bool recoverable)
  {
    if (failed()) {
      throw BusError(recoverable);
    }
    markAsFailed();
    return false;
  }

  /////
  //
  // pgl::Group::FDRecvTask method definitions
  //
  /////

  Group::FDRecvTask::FDRecvTask(int fd, void *recv_buffer, size_t recv_size, unsigned int usec_timeout)
    : Group::FDTask(fd, usec_timeout)
  {
    _size_received = 0;
    _size_total = recv_size;
    _buffer = reinterpret_cast<uint8_t*>(recv_buffer);
    _fd = -1;
    _receive_fd = false;
  }

  bool Group::FDRecvTask::run(Group& group)
  {
    if (receive()) {
      return process(group);
    }
    return false;
  }

  void Group::FDRecvTask::setReceiveBuffer(void *buffer)
  {
    _buffer = reinterpret_cast<uint8_t*>(buffer);
    return;
  }

  void Group::FDRecvTask::setReceiveSize(size_t size)
  {
    _size_total = size;
    return;
  }

  void Group::FDRecvTask::setReceiveFD()
  {
    _receive_fd = true;
    return;
  }

  bool Group::FDRecvTask::receive()
  {
    if (timeout()) {
      throw BusError(/*recoverable=*/true);
    }
    if (receiveData()) {
      return receiveFD();
    } else {
      return false;
    }
  }

  bool Group::FDRecvTask::receiveData()
  {
    if (_size_received == _size_total) {
      return true;
    }

    const size_t size_toread = _size_total - _size_received;
    uint8_t * const buffer = _buffer + _size_received;
    const ssize_t size_read = read(fd(), buffer, size_toread);

    if (size_read < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return false;
      }
      else {
        PGL_LOG() << "read failed with errno=" << errno;
        return failTask(/*recoverable=*/true);
      }
    }
    else if (size_read == 0) {
      /* EOF */
      return failTask(/*recoverable=*/false);
    }
    else {
      _size_received += size_read;
    }

    return _size_received == _size_total;
  }

  bool Group::FDRecvTask::receiveFD()
  {
    if (!_receive_fd) {
      return true;
    }

    _fd = readFD(fd(), 0);

    if (_fd != -1) {
      _receive_fd = false;
      return true;
    } else {
      return false;
    }
  }

  int Group::FDRecvTask::getFD() const
  {
    return _fd;
  }

  /////
  //
  // pgl::Group::FDSendTask method definitions
  //
  /////

  Group::FDSendTask::FDSendTask(int fd, void *send_buffer, size_t send_size, unsigned int usec_timeout)
    : Group::FDTask(fd, usec_timeout)
  {
    _size_written = 0;
    _size_total = send_size;
    _buffer = reinterpret_cast<const uint8_t*>(send_buffer);
    _fd = -1;
    _send_fd = false;
  }

  bool Group::FDSendTask::run(Group& group)
  {
    return send();
  }

  void Group::FDSendTask::setSendBuffer(const void *buffer)
  {
    _buffer = reinterpret_cast<const uint8_t*>(buffer);
    return;
  }

  void Group::FDSendTask::setSendSize(size_t size)
  {
    _size_total = size;
    return;
  }

  bool Group::FDSendTask::inProgress() const
  {
    return _size_written > 0;
  }

  bool Group::FDSendTask::send()
  {
    if (timeout()) {
      throw BusError(/*recoverable=*/true);
    }

    if (sendData()) {
      return sendFD();
    } else {
      return false;
    }
  }

  bool Group::FDSendTask::sendData()
  {
    if (_size_written == _size_total) {
      return true;
    }

    const size_t size_tosend = _size_total - _size_written;
    const uint8_t * const buffer = _buffer + _size_written;
    const ssize_t size_write = write(fd(), buffer, size_tosend);

    if (size_write < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
        return false;
      }
      else {
        PGL_LOG() << "write failed with errno=" << errno;
        return failTask(/*recoverable=*/false);
      }
    }
    else if (size_write == 0) {
      /* EOF */
      return failTask(/*recoverable=*/false);
    }
    else {
      _size_written += size_write;
    }

    return _size_written == _size_total;
  }

  bool Group::FDSendTask::sendFD()
  {
    if (!_send_fd) {
      return true;
    }

    if (writeFD(fd(), _fd, 0) != -1) {
      _send_fd = false;
      return true;
    } else {
      return false;
    }
  }

  void Group::FDSendTask::setSendFD(int fd)
  {
    _send_fd = true;
    _fd = fd;
    return;
  }

  /////
  //
  // pgl::Group::HeaderRecvTask method definitions
  //
  /////

  Group::HeaderRecvTask::HeaderRecvTask(int fd, unsigned int usec_timeout)
    : Group::FDRecvTask(fd, &_header, sizeof(Message::Header), usec_timeout)
  {
  }

  bool Group::HeaderRecvTask::process(Group& group)
  {
    /*
     * Inspect the received message header. If some check fails during the
     * inspection procedure, the method will handle the faulty process
     * accordingly and return false. We will therefore short-circuit the
     * current task and return true to the caller.
     */
    if (!group.inspectMessageHeader(_header, fd())) {
      PGL_LOG() << "Received header didn't pass the inspection procedure."
        << " Marking task as complete.";
      return true;
    }

    std::unique_ptr<FDTask> task(new MessageRecvTask(fd(), _header, group.getTaskRecvTimeout()));

    try {
      if (!task->run(group)) {
        group.masterAddReadTask(task.release());
      }
    } catch(...) {
      throw PGL_BUG("Unexpected exception caught during task execution.");
    }

    return true;
  }

  /////
  //
  // pgl::Group::MessageRecvTask method definitions
  //
  /////
  Group::MessageRecvTask::MessageRecvTask(int fd, const Message::Header& header, unsigned int usec_timeout)
    : Group::FDRecvTask(fd, nullptr, 0, usec_timeout),
      _msg(header)
  {
    setReceiveBuffer(_msg.dataWritable());
    setReceiveSize(_msg.dataSize());
    if (header.type == Message::Type::M2M_FD) {
      setReceiveFD();
    }
  }

  bool Group::MessageRecvTask::process(Group& group)
  {
    if (_msg.getTypeUnsafe() == Message::Type::M2M_FD) {
      _msg.setFD(getFD());
    }
    group.masterHandleBusMessage(std::move(_msg), fd());
    return true;
  }

  /////
  //
  // pgl::Group::MessageSendTask method definitions
  //
  /////

  Group::MessageSendTask::MessageSendTask(int fd, Message&& msg, unsigned int usec_timeout)
    : Group::FDSendTask(fd, nullptr, 0, usec_timeout),
      _msg(std::move(msg))
  {
    setSendBuffer(_msg.buffer());
    setSendSize(_msg.bufferSize());
    if (_msg.getType() == Message::Type::M2M_FD) {
      setSendFD(_msg.getFD());
    }
  }

} /* namespace pgl */
