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
#include <sys/signalfd.h>
#include <assert.h>

namespace pgl
{
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
    const std::string exec_name = Process::pathBasename(exec_path);
    const std::string arg0(argv[0]);
    const std::string arg0_name = Process::pathBasename(arg0);

    _exec_path = exec_path;
    _exec_name = exec_name;

    if (exec_name == arg0_name) {
      _master_mode = true;
      _member_instantiated = false;
    }
    else {
      _master_mode = false;
      _member_instantiated = false;

      if (arg0.find_first_of('/') == std::string::npos) {
	throw std::runtime_error("Cannot find out requested process name from argv[0]");
      }
      else {
	_requested_name = Process::pathBasename(arg0);
      }
    }

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
	int rfd = -1;
	process->getMessageBusFDs(&rfd, nullptr);
	_process_by_rfd[rfd] = process;
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
	    //++it;
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
} /* namespace pgl */
