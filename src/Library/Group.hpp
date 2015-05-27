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

#include "Process.hpp"
#include <iostream>
#include <string>
#include <map>
#include <queue>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <type_traits>
#include <unistd.h>
#include <climits>

namespace pgl
{
  class Group
  {
  public:
    Group(int argc, char *argv[]);
 
    template<class T>
    void addProcess(const std::string& name)
    {
      static_assert(std::is_base_of<Process, T>::value,
		    "T must be derived from Process");

      std::unique_lock<std::mutex> map_lock(_process_map_mutex);

      if (_master_mode) {
	/*
	 * The masterAddProcess method creates a Process instance for
	 * every process added to the group. The instance is put into
	 * an Process::Initialized state and is ready for spawning the
	 * real process by the Group::run() method.
	 */
	masterAddProcess<T>(name);
      }
      else {
	/*
	 * We are in a child process of the master. The memberAddProcess
	 * method will create a new instance of the process class iff
	 * it's the one that matches the requested one in argv[0]. Other
	 * requests will be ignored.
	 */
	memberAddProcess<T>(name);
      }

      return;
    }

    /*
     * Start the group (run the master process) or run a
     * specific process from the group.
     */
    int run();

  protected:
    class FDTask
    {
    public:
      FDTask(const int fd)
	: _fd(fd)
      {
      }
      bool operator==(const FDTask& rhs) const
      {
	return _fd == rhs._fd;
      }
      bool operator<(const FDTask& rhs) const
      {
	return _fd < rhs._fd;
      }
      bool operator>(const FDTask& rhs) const
      {
	return _fd > rhs._fd;
      }
      int fd() const
      {
	return _fd;
      }

      virtual bool run(Group& group) = 0;

    private:
      const int _fd;
    };

    class FDRecvTask : public FDTask
    {
    public:
      FDRecvTask(int fd, void *recv_buffer = nullptr, size_t recv_size = 0)
	: FDTask(fd)
      {
	_size_received = 0;
	_size_total = recv_size;
	_buffer = reinterpret_cast<uint8_t*>(recv_buffer);
      }

      bool run(Group& group) final
      {
	if (receive()) {
	  return process(group);
	}
	return false;
      }

      virtual bool process(Group& group) = 0;

      void setReceiveBuffer(void *buffer)
      {
	_buffer = reinterpret_cast<uint8_t*>(buffer);
	return;
      }

      void setReceiveSize(size_t size)
      {
	_size_total = size;
	return;
      }

    protected:
      bool receive()
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

    private:
      size_t _size_total;
      size_t _size_received;
      uint8_t *_buffer;
    };

    class FDSendTask : public FDTask
    {
    public:
      FDSendTask(int fd, void *send_buffer = nullptr, size_t send_size = 0)
	: FDTask(fd)
      {
	_size_written = 0;
	_size_total = send_size;
	_buffer = reinterpret_cast<const uint8_t*>(send_buffer);
      }

      bool run(Group& group) final
      {
	return send();
      }

      void setSendBuffer(const void *buffer)
      {
	_buffer = reinterpret_cast<const uint8_t*>(buffer);
	return;
      }

      void setSendSize(size_t size)
      {
	_size_total = size;
	return;
      }

      bool inProgress() const
      {
	return _size_written > 0;
      }

    protected:
      bool send()
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

    private:
      size_t _size_total;
      size_t _size_written;
      const uint8_t *_buffer;
    };

    class HeaderRecvTask : public FDRecvTask
    {
    public:
      HeaderRecvTask(int fd)
	: FDRecvTask(fd, &_header, sizeof(Message::Header))
      {
      }

      bool process(Group& group)
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

    private:
      Message::Header _header;
    };

    class MessageRecvTask : public FDRecvTask
    {
    public:
      MessageRecvTask(int fd, const Message::Header& header)
	: FDRecvTask(fd),
	  _msg(header)
      {
	setReceiveBuffer(_msg.dataWritable());
	setReceiveSize(_msg.dataSize());
      }

      bool process(Group& group)
      {
	group.masterHandleBusMessage(_msg, fd());
	return true;
      }

    private:
      Message _msg;
    };

    class MessageSendTask : public FDSendTask
    {
    public:
      MessageSendTask(int fd, Message& msg)
	: FDSendTask(fd),
	  _msg(std::move(msg))
      {
	setSendBuffer(_msg.buffer());
	setSendSize(_msg.bufferSize());
      }

    private:
      Message _msg;
    };
    
    void masterHandleBusMessage(Message& msg, int from_fd)
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

    void masterRouteMessage(Message& msg)
    {
      const pid_t pid_to = msg.getTo();
      auto const& process = _process_by_pid[pid_to];
      int fd = -1;
      process->getMessageBusFDs(nullptr, &fd);
      std::shared_ptr<FDTask> task = std::make_shared<MessageSendTask>(fd, msg);
      masterAddWriteTask(task);
      return;
    }

    void masterPIDLookupReply(Message& msg, int from_fd)
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

    template<class T>
    void masterAddProcess(const std::string& name)
    {
      auto const& map_entry_it = _process_by_name.find(name);

      /*
       * If there's already a process registered under the
       * same name, check that the newly added process has
       * a compatible class. We do this by trying to
       * dynamic_cast the existing process instance to the
       * class of the process that's being added.
       */
      if (map_entry_it != _process_by_name.end()) {
	if (!std::dynamic_pointer_cast<T>(map_entry_it->second)) {
	  throw std::runtime_error("Cannot add process: procesees with a shared name have to be of the same class");
	}
      }

      auto derived_ptr = std::make_shared<T>();
      auto process_ptr = std::dynamic_pointer_cast<Process>(derived_ptr);

      process_ptr->setName(name);
      /* PID set on spawn() */
      process_ptr->setExecPath(_exec_path);

      _process_by_name.emplace(name, process_ptr);

      return;
    }

    template<class T>
    void memberAddProcess(const std::string& name)
    {
      if (_member_instantiated) {
	/* Ignore: already instantiated */
	return;
      }
      if (_requested_name != name) {
	/* Ignore: this class is not the requested one */
	return;
      }

      auto derived_ptr = std::make_shared<T>();
      auto process_ptr = std::dynamic_pointer_cast<Process>(derived_ptr);

      process_ptr->setName(name);
      process_ptr->setPID(::getpid());
      process_ptr->setExecPath(_exec_path);
      process_ptr->setMessageBusFDs(/*rfd=*/0, /*wfd*/1);

      _process_by_name.emplace(name, process_ptr);
      _process_by_pid.emplace(::getpid(), process_ptr);

      _member_instantiated = true;

      return;
    }

    int masterRun();
    void masterStartProcesses();
    void masterStopProcesses();
    void masterProcessEvents();
    int groupExitCode();
    int memberRun();

    void masterReceiveSignal();
    void masterReceiveHeader(int fd);
    void masterAddReadTask(std::shared_ptr<FDTask>& task);
    void masterAddWriteTask(std::shared_ptr<FDTask>& task);
  private:
    int _process_argc;
    char **_process_argv;

    std::string _exec_path;
    std::string _exec_name;

    //
    // Map mutex. Anything that touches _process_by_name or
    // _process_by_pid has to create a lock using this mutex
    //
    std::mutex _process_map_mutex;
    //
    // There can be multiple processes with the same name
    //
    std::multimap<std::string, std::shared_ptr<Process> > _process_by_name;
    //
    // PIDs are unique, therefore we use unordered_map here
    //
    std::unordered_map<pid_t, std::shared_ptr<Process> > _process_by_pid;
    //
    //
    //
    std::unordered_map<pid_t, std::shared_ptr<Process> > _process_by_rfd;
    //
    // Is the current process the master process?
    //
    bool _master_mode;
    //
    // In member mode (non-master) mode, this flag
    // will be set if the process implementation instance
    // was created.
    //
    bool _member_instantiated;
    //
    // What is the requested name for the process? (from argv[0])
    // Must be empty for the master process
    //
    std::string _requested_name;

    int _signal_fd;

    std::unordered_map<int, std::queue<std::shared_ptr<FDTask> > > _tasks_rd;
    std::unordered_map<int, std::queue<std::shared_ptr<FDTask> > > _tasks_wr;
  };
} /* namespace pgl */
