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
#include "Timeout.hpp"
#include "Exceptions.hpp"
#include <string>
#include <map>
#include <queue>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <type_traits>
#include <unistd.h>
#include <limits.h>
#include <iostream>
#include <sys/select.h>

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
          "T must be derived from pgl::Process");

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

    void setTaskSendTimeout(unsigned int usec);
    unsigned int getTaskSendTimeout() const;
    void setTaskRecvTimeout(unsigned int usec);
    unsigned int getTaskRecvTimeout() const;

    void setMessageSizeLimit(size_t bytes);
    size_t getMessageSizeLimit() const;

    enum class TerminationAction {
      Restart,
      Terminate
    };

  protected:
    class FDTask
    {
    public:
      FDTask(const int fd, unsigned int usec_timeout = -1);
      virtual ~FDTask() {}
      bool operator==(const FDTask& rhs) const;
      bool operator<(const FDTask& rhs) const;
      bool operator>(const FDTask& rhs) const;
      int fd() const;
      const Timeout& timeout() const;
      bool failed() const;
      void markAsFailed();
      pid_t relatedPID() const;
      void setRelatedPID(pid_t pid);

      virtual bool run(Group& group) = 0;

    protected:
      bool failTask(bool recoverable);

    private:
      const int _fd;
      Timeout _timeout;
      bool _failed;
      pid_t _related_pid;
    };

    class FDRecvTask : public FDTask
    {
    public:
      FDRecvTask(int fd, void *recv_buffer = nullptr, size_t recv_size = 0, unsigned int usec_timeout = -1);
      virtual ~FDRecvTask() {}

      bool run(Group& group) final;
      void setReceiveBuffer(void *buffer);
      void setReceiveSize(size_t size);
      void setReceiveFD();
      int getFD() const;

      virtual bool process(Group& group) = 0;

    protected:
      bool receive();
      bool receiveData();
      bool receiveFD();

    private:
      size_t _size_total;
      size_t _size_received;
      uint8_t *_buffer;
      int _fd;
      bool _receive_fd;
    };

    class FDSendTask : public FDTask
    {
    public:
      FDSendTask(int fd, void *send_buffer = nullptr, size_t send_size = 0, unsigned int usec_timeout = -1);
      virtual ~FDSendTask() {}
      bool run(Group& group) final;
      void setSendBuffer(const void *buffer);
      void setSendSize(size_t size);
      void setSendFD(int fd);
      bool inProgress() const;

    protected:
      bool send();
      bool sendData();
      bool sendFD();

    private:
      size_t _size_total;
      size_t _size_written;
      const uint8_t *_buffer;
      int _fd;
      bool _send_fd;
    };

    class HeaderRecvTask : public FDRecvTask
    {
    public:
      HeaderRecvTask(int fd, unsigned int usec_timeout = -1);
      bool process(Group& group) final;

    private:
      Message::Header _header;
    };

    class MessageRecvTask : public FDRecvTask
    {
    public:
      MessageRecvTask(int fd, const Message::Header& header, unsigned int usec_timeout = -1);
      bool process(Group& group) final;

    private:
      Message _msg;
    };

    class MessageSendTask : public FDSendTask
    {
    public:
      MessageSendTask(int fd, Message&& msg, unsigned int usec_timeout = -1);

    private:
      Message _msg;
    };

    /////
    //
    // Group: protected methods
    //
    /////
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

      /*
       * NOTE: PID is set in the Process::spawn() method when the master
       *       process calls it
       */
      process_ptr->setName(name);
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
      process_ptr->setMessageBusFDs(/*rfd=*/_member_bus_rfd, /*wfd=*/_member_bus_wfd);
      process_ptr->setSignalFD(_signal_fd);

      _process_by_name.emplace(name, process_ptr);
      _process_by_pid.emplace(::getpid(), process_ptr);

      _member_instantiated = true;

      return;
    }

    int masterRun();
    int memberRun();
    void masterStartProcesses();
    void masterStopProcesses();
    void masterMainloopCollectActiveFDs(fd_set& rd_set, fd_set& wr_set,
        int& max_fd, int& max_rfd);
    bool masterMainloopTerminated() const;
    int masterMainloopWaitForEvents(fd_set& rd_set, fd_set& wr_set, int max_fd);
    void masterMainloopProcessWriteEvents(fd_set& wr_set);
    void masterMainloopProcessReadEvents(fd_set& rd_set, int max_rfd);
    void masterMainloopProcessEvents(fd_set& rd_set, fd_set& wr_set, int max_rfd);
    void masterMainloop();
    int masterGetExitCode();
    void masterSetExitCode(int exit_code);
    void masterReceiveSignal();
    void masterHandleMemberTermination(pid_t pid);
    TerminationAction masterGetMemberTerminationAction(pid_t pid);
    void masterRestartMember(pid_t pid);
    void masterReceiveHeader(int fd);
    void masterAddReadTask(FDTask* task);
    void masterAddWriteTask(FDTask* task);
    void masterHandleBusMessage(Message&& msg, int from_fd);
    void masterRouteMessage(Message&& msg);
    void masterPIDLookupReply(Message&&, int from_fd);
    void masterTerminate();
    void masterSetTerminationTimeout(unsigned int usec);
    bool inspectMessageHeader(const Message::Header& header, int fd);
    std::shared_ptr<Process> getProcessByFD(int fd);
    std::shared_ptr<Process> getProcessByPID(pid_t pid);
    /**
     * Removes process instance from the process-by-pid, process-by-fd map
     * and tasks related to the process fds.
     */
    void removeProcessRelatedState(std::shared_ptr<Process>& process);

  private:
    /*
     * argc and argv values the were passed to the main()
     * function of the process. These values are forwarded
     * to each member process.
     */
    int _process_argc;
    char **_process_argv;
    /*
     * Absolute path to the executable. Read from /proc/self/exec.
     */
    std::string _exec_path;
    /*
     * PGL_EXEC_NAME environment variable value.
     */
    std::string _exec_name;
    /*
     * Map mutex. Anything that touches _process_by_name or
     * _process_by_pid has to create a lock using this mutex
     */
    std::mutex _process_map_mutex;
    /*
     * Map of process names to their pgl::Process instances. There
     * can be multiple pgl::Process instances with the same name.
     */
    std::multimap<std::string, std::shared_ptr<Process> > _process_by_name;
    /*
     * Map of active PIDs to their pgl::Process instances. PIDs are
     * unique, therefore we use unordered_map here.
     */
    std::unordered_map<pid_t, std::shared_ptr<Process> > _process_by_pid;
    /*
     * Map of active FDs to their pgl::Process instances.
     */
    std::unordered_map<int, std::shared_ptr<Process> > _process_by_fd;
    /*
     * Maste mode flag. Set in constructor based on the PGL_EXEC_NAME environment
     * variable. If set, then the current process should run as the group master,
     * spawn the members and process message bus requests and message routing.
     */
    bool _master_mode;
    /*
     * In member mode (non-master) mode, this flag will be set if the process
     * implementation instance was created. This prevents creating new instances
     * of the same class if multiple members share the same name (and therefore
     * share the same class -- which is enforced using a type check in
     * memberAddProcess)
     */
    bool _member_instantiated;
    /*
     * What is the requested name for the process? (from PGL_EXEC_NAME environment
     * variable). Must be left empty for the master process.
     */
    std::string _requested_name;
    /*
     * Master received signal using an fd. See signalfd(2).
     */
    int _signal_fd;
    /*
     * Map of file descriptors to their read task queues.
     */
    std::unordered_map<int, std::queue<FDTask*> > _tasks_rd;
    /*
     * Map of file descriptors to their write task queues.
     */
    std::unordered_map<int, std::queue<FDTask*> > _tasks_wr;
    /*
     * Group termination flag
     */
    bool _group_terminate;
    /*
     * Exit code of the master process
     */
    int _group_exit_code;
    /*
     * Timeout object for the graceful termination period
     */
    Timeout _graceful_termination_timeout;
    /*
     * Task send task timeout
     */
    unsigned int _task_send_timeout_usec;
    /*
     * Task recv task timeout
     */
    unsigned int _task_recv_timeout_usec;
    /*
     * Message size limit in bytes. Applies only to the
     * data part of the message.
     */
    size_t _message_size_limit;
    /*
     * File descriptors for the member to use as the message bus
     * file descriptors (write fd, read fd)
     */
    int _member_bus_wfd;
    int _member_bus_rfd;
  };
} /* namespace pgl */
