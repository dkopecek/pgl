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

#include "Message.hpp"
#include <string>
#include <mutex>
#include <random>
#include <queue>
#include <atomic>
#include <cstdint>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/socket.h>

namespace pgl
{
  class Process
  {
  public:
    enum State
      {
        Initialized, /**< Never started; This state is set for new instances */
        Running, /**< The process is considered to be running */
        Finished, /**< The process finished execution without any intervention from the master process */
        Terminated, /**< The process was terminated by the master process */
        Failed, /**< A failure caused the process to not start/or terminate */
        Invalid /**< The instance is in invalid/unusable state */
      };

    Process();
    virtual ~Process();

    const std::string& getName() const;
    void setName(const std::string& name);
    void setPID(const pid_t pid);
    pid_t getPID() const;
    void setState(Process::State state);
    State getState() const;
    void setExecPath(const std::string& exec_path);
    const std::string& getExecPath() const;
    void setMessageBusFDs(int rfd, int wfd);
    void getMessageBusFDs(int *rfd_ptr, int *wfd_ptr);
    void setCloseAllFDs(unsigned int from_fd);

    /**
     * Message Bus Send operation timeout.
     * This method sets the maximum amount of time, specified in microseconds,
     * that a send operation is allowed to consume.
     *
     * If the operation doesn't complete in the specified time, it'll throw
     * a BusError exception. Depending on whether any data was sent or not, the
     * recoverable flag of the BusError exception will be set (no data sent) or
     * not (some data already sent). The operation may be attempted again if
     * the recoverable flag is set to true.
     *
     * Applies to the following methods:
     *  messageBusSend
     *  messageBusSendFD
     */
    void setMessageBusSendTimeout(unsigned int usec);

    /**
     * Message Bus Receive operation timeout.
     * This method sets the maximum amount of time, specified in microseconds,
     * that a receive operation is allowed to consume.
     *
     * If the operation doesn't complete in the specified time, it'll throw
     * a BusError exception. Depending on whether any data was received or not,
     * the recoverable flag of the BusError exception will be set (no data
     * received) or not (some data received, but not all). The operation may be
     * attempted again if the recoverable flag is set to true.
     *
     * Applies to:
     *  messageBusRecv
     *  messageBusRecvFD
     */
    void setMessageBusRecvTimeout(unsigned int usec);

    //
    // TODO
    //
    //void setRunAsUser();
    //void setRunAsGroup();
    //void setChroot();
    //void setLinuxCapabilities();
    //void setLinuxSeccompFilter(void *scmp_filter_ctx_ptr);
    //void setResourceLimit();
    //void setMessageBusSizeLimit(size_t bytes_max);
    //void setMLockedMemory(size_t bytes_max); /**< alloc+mlock+setrlimit */

    /*
     * Method called right before calling exec(3)
     * to start the process from it's master/parent
     * process
     */
    virtual void preExecSetup();

    /*
     * Method called inside the newly created process
     * right before entering the process main loop.
     */
    virtual void postExecSetup();

    /*
     * Process main loop.
     * This function will be executed in a separate process.
     */
    virtual int main(int argc, char * argv[]) = 0;

    /*
     * Resolve a process name to it's current PID.
     *
     * Returns -1 of the name couldn't be resolved.
     */
    pid_t messageBusResolve(const std::string& name);

    /*
     *  1 ... data waiting
     *  0 ... timed out
     * -1 ... interrupted
     */
    int messageBusWait(unsigned int max_wait_usec = 0);

    /*
     * Send a message to another process identified by it's PID.
     * If peer_pid == -1, the message will be broadcasted to all
     * running processes in the group.
     */
    void messageBusSend(pid_t peer_pid, const std::string& message);

    /*
     * Receive a message from the message bus. If peer_pid is == -1,
     * then any message addressed to this process will be recevied.
     * Otherwise, the sending process PID has to match the value
     * of peer_pid.
     *
     * Returns -1 when no message was received. Otherwise, the PID
     * of the sending process is returned. An exception is thrown
     * on failure.
     */
    pid_t messageBusRecv(pid_t peer_pid, std::string& message);

    void messageBusSendFD(pid_t peer_pid, int fd, const std::string& message = "");

    pid_t messageBusRecvFD(pid_t peer_pid, int *fd, std::string *message = nullptr);

    /**/
    pid_t messageBusSendRecv(pid_t peer_pid, const std::string& message, std::string& reply);

    Message messageBusSendRecv(Message& msg, Message::Type recv_type);
    void messageBusSend(Message& msg, bool lock_bus = true);

    /*
     * Receive a message of the specified type. Message of different types
     * will be queued in the receiving queue.
     */
    Message messageBusRecvMessage(Message::Type type, bool lock_bus);
    /*
     * Receive a message (of any type) from the message bus.
     */
    Message messageBusRecvMessage(bool lock_bus = true);

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

    pid_t spawn(int argc, char * argv[]);
    void stop();
    void kill();

    static const std::string pathBasename(const std::string& path);
  protected:
    static void messageBusWrite(int fd, const uint8_t *data, size_t size, unsigned int max_delay_usec);
    static void messageBusRead(int fd, uint8_t *data, size_t size, unsigned int max_delay_usec);
    static void messageBusWriteFD(int bus_fd, int fd, unsigned int max_delay_usec);
    static int messageBusReadFD(int bus_fd, unsigned int max_delay_usec);

    void terminate(int signal);
    uint8_t expectedMessageHashBytePosition();
    uint8_t messageHashByteAt(size_t pos, const Message::Header* header, const uint8_t *data, size_t size);
    void prepareMemberEnvVariables(char **& env_array);

    /*
     * Put the message in the receive queue.
     */
    void messageBusRecvEnqueue(Message&& msg);

    /*
     * Get a message from receive queue.
     */
    Message messageBusRecvDequeue(Message::Type type, bool lock_bus);

    /*
     * Check whether a message is queued for receiving.
     */
    bool messageBusRecvQueued(Message::Type type) const;

  private:
    std::string _name;
    std::string _exec_path;
    std::string _exec_name;
    std::vector<std::string> _keep_env;

    pid_t _pid;
    pid_t _pid_master;

    std::mutex _bus_wfd_mutex;
    int _bus_wfd;

    std::mutex _bus_rfd_mutex;
    int _bus_rfd;

    std::queue<Message> _bus_recv_queue[Message::type_count];
    std::atomic<bool> _bus_recv_queued[Message::type_count];

    State _state;

    std::default_random_engine _rng_hashbyte;
    std::uniform_int_distribution<uint8_t> _rnd_hashbyte;

    unsigned int _closeall_fds;

    unsigned int _bus_send_timeout_usec;
    unsigned int _bus_recv_timeout_usec;
  };
} /* namespace pgl */
