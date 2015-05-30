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
#include "Process.hpp"
#include "Utility.hpp"
#include <sys/signalfd.h>
#include <assert.h>
#include <time.h>

namespace pgl
{
  /////
  //
  // pgl::Group method definitions
  //
  /////

  Group::Group(int argc, char *argv[])
    : _process_argc(argc),
      _process_argv(argv)
  {
    if (argc < 1 || argv == nullptr) {
      throw std::runtime_error("Invalid argc, argv[] parameter values");
    }
    if (argv[0] == nullptr) {
      throw std::runtime_error("argv[0] is NULL");
    }

    //
    // Find out the process mode from the exectable path
    // and argv[0] value
    //
    char path_buffer[PATH_MAX];
    const ssize_t path_length = ::readlink("/proc/self/exe",
					   path_buffer, sizeof path_buffer);

    if (path_length == -1) {
      throw std::runtime_error("Cannot get executable path of the current process");
    }

    const std::string exec_path(path_buffer, path_length);
    const char * exec_name_env = getenv("PGL_EXEC_NAME");
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
    
      if ((_signal_fd = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC)) == -1) {
	throw std::runtime_error("Cannot create signal fd");
      }
    }
    else {
      _master_mode = false;
      _member_instantiated = false;
      _requested_name = exec_name;
      _signal_fd = -1;
    }

    return;
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
    masterProcessEvents();
    masterStopProcesses();
    return groupExitCode();
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
  
  //
  // TODO: Refactor the mess in the method below
  //
  void Group::masterProcessEvents()
  {
    for (;;) {
      fd_set rd_set;
      fd_set wr_set;

      /* Initialize */
      FD_ZERO(&rd_set);
      FD_ZERO(&wr_set);

      int max_fd = -1;
      int max_rfd = -1;
      struct timeval tv_timeout = { 10, 0 /*us*/ };

      /*
       * Collect fds
       */
      FD_SET(_signal_fd, &rd_set);
      max_fd = _signal_fd;

      for (auto const& map_entry : _process_by_pid) {
	auto const& process = map_entry.second;
	int fd = -1;
	process->getMessageBusFDs(&fd, nullptr);
	if (fd == -1) {
	  throw std::runtime_error("BUG: getMessageBusFDs() returned an invalid fd");
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

      /*
       * Wait for events
       */
      const int nfds = select(max_fd + 1, &rd_set, &wr_set, nullptr, &tv_timeout);

      if (nfds == -1) {
	return;
      }
      else if (nfds == 0) {
	continue;
      }

      /*
       * Handle signals first
       */
      if (FD_ISSET(_signal_fd, &rd_set)) {
	masterReceiveSignal();
	FD_CLR(_signal_fd, &rd_set);
      }

      /*
       * Handle writes before reads to free some memory
       */
      for (auto it = _tasks_wr.begin(); it != _tasks_wr.end(); ) {
	const int fd = it->first;

	if (FD_ISSET(fd, &wr_set)) {
	  auto& queue = it->second;

	  if (queue.empty()) {
	    ++it;
	    continue;
	  }

	  auto& task = queue.front();
	  assert(task->fd() == fd);

	  if (task->run(*this)) {
	    queue.pop();
	  }

	  if (queue.empty()) {
	    it = _tasks_wr.erase(it);
	    continue;
	  }
	}

	++it;
      } /* write task loop end */

      /* Handle reads */
      for (int fd = 0; fd <= max_rfd; ++fd) {
	if (FD_ISSET(fd, &rd_set)) {
	  if (_tasks_rd.count(fd) == 0) {
	    /* Create a new RecvHeaderTask */
	    masterReceiveHeader(fd);
	  }
	  else {
	    /* Handle existing read task */
	    auto& queue = _tasks_rd[fd];

	    if (queue.empty()) {
	      continue;
	    }

	    auto& task = queue.front();
	    
	    if (task->run(*this)) {
	      queue.pop();
	      if (queue.empty()) {
		_tasks_rd.erase(fd);
	      }
	    }
	  }
	}
      } /* read fd loop */

    } /* select loop */

    return;
  }

  void Group::masterReceiveSignal()
  {
    struct signalfd_siginfo sig;

    // NOTE: Tolerate EAGAIN, EINTR here?
    if (read(_signal_fd, &sig, sizeof sig) != sizeof sig) {
      throw std::runtime_error("Failed to read signal info from signal fd");
    }

    return;
  }

  void Group::masterReceiveHeader(int fd)
  {
    std::shared_ptr<FDTask> task = std::make_shared<Group::HeaderRecvTask>(fd);

    if (task->run(*this)) {
      return;
    }
    /*
     * Completion of the task would block the thread, add
     * it to read tasks. It'll be completed then the fd becoms
     * readable again.
     */
    masterAddReadTask(task);
    return;
  }

  int Group::groupExitCode()
  {
    return EXIT_SUCCESS;
  }

  int Group::memberRun()
  {
    std::unique_lock<std::mutex> map_lock(_process_map_mutex);
    auto& process = _process_by_pid[::getpid()];
    process->postExecSetup();
    process->setState(Process::State::Running);
    return process->main(_process_argc, _process_argv);
  }

  void Group::masterAddReadTask(std::shared_ptr<FDTask>& task)
  {
    const int fd = task->fd();
    _tasks_rd[fd].push(task);
    return;
  }

  void Group::masterAddWriteTask(std::shared_ptr<FDTask>& task)
  {
    const int fd = task->fd();
    _tasks_wr[fd].push(task);
    return;
  }

  void Group::masterHandleBusMessage(Message& msg, int from_fd)
  {
    msg.validate();

    switch(msg.getType())
      {
      case Message::Type::M2M:
	masterRouteMessage(msg);
	break;
      case Message::Type::BUS_PID_LOOKUP:
	masterPIDLookupReply(msg, from_fd);
	break;
      default:
	throw std::runtime_error("Unknown message type");
      }

    return;
  }

  void Group::masterRouteMessage(Message& msg)
  {
    const pid_t pid_to = msg.getTo();
    auto const& process = _process_by_pid[pid_to];
    int fd = -1;
    process->getMessageBusFDs(nullptr, &fd);
    std::shared_ptr<FDTask> task = std::make_shared<MessageSendTask>(fd, msg);
    masterAddWriteTask(task);
    return;
  }

  void Group::masterPIDLookupReply(Message& msg, int from_fd)
  {
    const std::string name(reinterpret_cast<const char *>(msg.data()), msg.dataSize());
    pid_t pid = -1;

    auto range = _process_by_name.equal_range(name);
    for (auto entry = range.first; entry != range.second; ++entry) {
      auto process = entry->second;
      pid = process->getPID();
      break;
    }

    Message reply(sizeof(pid_t));
    reply.setFrom(0);
    reply.setTo(msg.getFrom());
    reply.setType(Message::Type::BUS_PID_LOOKUP);
    reply.copyToData(&pid, sizeof (pid_t));
    reply.finalize();

    std::shared_ptr<FDTask> task = std::make_shared<MessageSendTask>(from_fd, reply);
    masterAddWriteTask(task);
    return;
  }

  /////
  //
  // pgl::Group::FDTask method definitions
  //
  /////

  Group::FDTask::FDTask(const int fd)
    : _fd(fd)
  {
    _ts_created.tv_sec = 0;
    _ts_created.tv_nsec = 0;

    if (clock_gettime(CLOCK_MONOTONIC, &_ts_created) != 0) {
      throw std::runtime_error("clock_gettime failed");
    }
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

  uint64_t Group::FDTask::currentAgeMicrosec() const
  {
    struct timespec ts_now;

    ts_now.tv_sec = 0;
    ts_now.tv_nsec = 0;

    if (clock_gettime(CLOCK_MONOTONIC, &ts_now) != 0) {
      throw std::runtime_error("clock_gettime failed");
    }

    return tsMicrosecDiff(ts_now, _ts_created);
  }

  /////
  //
  // pgl::Group::FDRecvTask method definitions
  //
  /////

  Group::FDRecvTask::FDRecvTask(int fd, void *recv_buffer, size_t recv_size)
    : Group::FDTask(fd)
  {
    _size_received = 0;
    _size_total = recv_size;
    _buffer = reinterpret_cast<uint8_t*>(recv_buffer);
    _max_duration_usec = 0;
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

  bool Group::FDRecvTask::receive()
  {
    if (_size_received == _size_total) {
      return true;
    }
    if (_max_duration_usec != 0
	&& currentAgeMicrosec() > _max_duration_usec) {
      throw std::runtime_error("recv timeout");
    }

    const size_t size_toread = _size_total - _size_received;
    uint8_t * const buffer = _buffer + _size_received;
    const ssize_t size_read = read(fd(), buffer, size_toread);

    if (size_read < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	return false;
      }
      else {
	throw std::runtime_error("FDRecvTask failed");
      }
    }
    else if (size_read == 0) {
      throw std::runtime_error("fd closed");
    }
    else {
      _size_received += size_read;
    }

    return _size_received == _size_total;
  }

  /////
  //
  // pgl::Group::FDSendTask method definitions
  //
  /////

  Group::FDSendTask::FDSendTask(int fd, void *send_buffer, size_t send_size)
    : Group::FDTask(fd)
  {
    _size_written = 0;
    _size_total = send_size;
    _buffer = reinterpret_cast<const uint8_t*>(send_buffer);
    _max_duration_usec = 0;
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
    if (_size_written == _size_total) {
      return true;
    }
    if (_max_duration_usec != 0
	&& currentAgeMicrosec() > _max_duration_usec) {
      throw std::runtime_error("send timeout");
    }

    const size_t size_tosend = _size_total - _size_written;
    const uint8_t * const buffer = _buffer + _size_written;
    const ssize_t size_write = write(fd(), buffer, size_tosend);

    if (size_write < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	return false;
      }
      else {
	throw std::runtime_error("FDRecvTask failed");
      }
    }
    else if (size_write == 0) {
      throw std::runtime_error("fd closed");
    }
    else {
      _size_written += size_write;
    }

    return _size_written == _size_total;
  }

  /////
  //
  // pgl::Group::HeaderRecvTask method definitions
  //
  /////

  Group::HeaderRecvTask::HeaderRecvTask(int fd)
    : Group::FDRecvTask(fd, &_header, sizeof(Message::Header))
  {
  }

  bool Group::HeaderRecvTask::process(Group& group)
  {
    //
    // TODO: check sender pid
    // TODO: check size limits
    //
    std::shared_ptr<FDTask> task = std::make_shared<MessageRecvTask>(fd(), _header);

    if (!task->run(group)) {
      group.masterAddReadTask(task);
    }

    return true;
  }

  /////
  //
  // pgl::Group::MessageRecvTask method definitions
  //
  /////

  Group::MessageRecvTask::MessageRecvTask(int fd, const Message::Header& header)
    : Group::FDRecvTask(fd),
      _msg(header)
  {
    setReceiveBuffer(_msg.dataWritable());
    setReceiveSize(_msg.dataSize());
  }

  bool Group::MessageRecvTask::process(Group& group)
  {
    group.masterHandleBusMessage(_msg, fd());
    return true;
  }

  /////
  //
  // pgl::Group::MessageSendTask method definitions
  //
  /////

  Group::MessageSendTask::MessageSendTask(int fd, Message& msg)
    : Group::FDSendTask(fd),
      _msg(std::move(msg))
  {
    setSendBuffer(_msg.buffer());
    setSendSize(_msg.bufferSize());
  }

} /* namespace pgl */
