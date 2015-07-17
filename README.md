# pgl - Process Group Library

A C++ library that provides an API which simplifies the task of process isolation implementation

## Goals

### Primary goal

The primary goal is to develop a library that provides a C++ API which allows an application creator to define a group of interconnected processes and build the application using these processes. The library takes care of creating the processes, setting up the communication channels and handling the message routing and delivery. This is useful either from a security point of view, as each process can be stripped off priviledges to a minimal required set, or from a reliability point of view, because if a process in a group of separated processes crashes, it won't unexpectedly terminate the other processes.

### Secondary goals

* Provide a pre-implemented set of common processes with documented interfaces (e.g. an "ssh-agent" like process, a server process, command execution process, etc.)

* Experiment with support for monitoring process statistics and analysing process behaviour for anomalies.

## Status

The library is in early stages. It's development was triggered by a need to separate various processes inside the daemon component of the [USBGuard project](https://github.com/dkopecek/usbguard). It could have been just implemented inside the project, but the author thinks that it might be generaly useful to other C++ projects that aim for security or reliability.

## Documentation

With current API, it's possible to define a group of processes, start them and use API functions to send and receive unstructured messages to any member of the group.

### pgl::Process

A process is implemented as a subclass of the API-provided class, `pgl::Process`. In your subclass, you have to implement a method with type signature equal to that of a standard process entry-point function, `int main(int argc, char *argv[])`:

```c++
class MyProcess : public pgl::Process
{
    int main(int argc, char *argv[]);
};
```

From inside that function, you can call API functions to comminucate with other processes of the group:

```c++
void messageBusSend(pid_t peer_pid, const std::string& msg);
```
 * __messageBusSend__.
  Send a message stored in `msg` to a process with PID `peer_pid`. The `peer_pid` can be set to `-1` to indicate, that the message should be sent to all running processes in the group.


```c++
pid_t messageBusRecv(pid_t peer_pid, std::string& msg);
```
* __messageBusRecv__.
  Receive a message from process with PID `peer_pid` and store it in `msg`. The `peer_pid` can be set to `-1` to indicate that the message can be received from any processes from the group.


```c++
pid_t messageBusSendRecv(pid_t peer_pid, const std::string& msg, std::string& msg_reply);
```
* __messageBusSendRecv__.
  Send a message stored in `msg` to a process with PID `peer_pid`, wait for a reply and store it in `msg_reply`.


```c++
void messageBusSendFD(pid_t peer_pid, int fd, const std::string& message = "");
```
* __messageBusSendFD__.
  Send a message with a file descriptor `fd` to a process with PID `peer_pid`. The `peer_pid` can be set to `-1` to indicate, that the message should be sent to all running processes in the group.


```c++
pid_t messageBusRecvFD(pid_t peer_pid, int *fd, std::string *message = nullptr);
```
* __messageBusRecvFD__.
  Receive a message with a file descriptor from a process with PID `peer_pid`. The `peer_pid` can be set to `-1` to indicate that the message can be received from any process from the group. If a non-NULL pointer to a `std::string` object is provided in `message`, then the message sent along with the fd will be stored there.


If you want to send a message to a specific process, first you have to resolve its name to its current PID. You can do that by using:

```c++
pid_t messageBusResolve(const std::string& name);
```
* __messageBusResolve__.
  Resolve a string identifier of a member of the group to the PID of a running process with that identifier. If there's no active process with such a name, `-1` is returned.


```c++
int messageBusWait(unsigned int max_wait_usec = 0);
```
* __messageBusWait__.
  Wait for a message. The `max_wait_usec` parameter specifies how long, in microseconds, to wait for a message to appear on the bus. If set to 0, the call will block until a message is available or until the wait is interrupted by an external event (e.g. signal). If a message is available, 1 is returned. On interruption, -1 is returned. If `max_wait_usec` is non-zero and the timeout expired, 0 is returned.


### pgl::Group

Defining the group is done by instantiating the `pgl::Group` class inside the standard main function and registering your `pgl::Process` sub-classes in the instance using the `addProcess<typename T>(const std::string& name);` method of the `pgl::Group` class:

```c++
int main(int argc, char *argv[])
{
    pgl::Group group(argc, argv);
    
    group.addProcess<MyProcess>("MyProcess1");
    group.addProcess<MyProcess>("MyProcess2");
    
    return group.run();
}
```

The `pgl::Group` constructor takes the original `argc` and `argv` values. When a member process is spawned, these values are forwarded to its `main()` function.

After we are done registering processes, we can start the process group by calling the `run()` method of the `pgl::Group` class. The function returns only after all member of the group cease to exist on the system. The return value of the function should be used as the return value of the standard `main()` function as it indicates whether the group terminated successfully or not.

Sources of several demo applications that show how to use the API are located in the [src/Examples/](src/Examples) sub-directory in the repository. The [minprivs](src/Examples/minprivs.cpp) demo application shows how to drop all kinds of priviledges and access to OS resources while still be able to use the API. That application assumes that it'll be started under the *root* user.
