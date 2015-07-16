#include <iostream>
#include <unistd.h>
#include <cstdint>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "Group.hpp"

/*
 * Open fd on request and send it to the requesting process
 */
class OpenProcess : public pgl::Process
{
public:
  int main(int argc, char *argv[])
  {
    for (;;) {
      if (messageBusWait() != 1) {
	continue;
      }

      /* receive request */
      std::string message;
      const pid_t peer_pid = messageBusRecv(-1, message);
      /* open fd */
      const int fd = open(message.c_str(), O_WRONLY|O_CREAT, S_IRWXU);

      if (fd == -1) {
	abort();
      }

      /* send fd */
      messageBusSendFD(peer_pid, fd, message);
    }
    return 0;
  }
};

/*
 * Request an fd from the open process and write received
 * string messages to the fd
 */
class WriteProcess : public pgl::Process
{
public:
  int main(int argc, char *argv[])
  {
    const pid_t open_pid = messageBusResolve("OpenProcess");
    int fd = -1;

    /* request fd */
    messageBusSend(open_pid, "/tmp/test.log");
    while(messageBusRecvFD(open_pid, &fd) == -1);

    for (;;) {
      /* wait for a message */
      if (messageBusWait() != 1) {
	continue;
      }

      /* receive the message */
      std::string message;
      messageBusRecv(-1, message);

      /* write it to the fd */
      write(fd, message.c_str(), message.size());
    }

    return 0;
  }
};

/* Send one message per seconds to the write process */
class MessageProcess : public pgl::Process
{
public:
  int main(int argc, char *argv[])
  {
    const pid_t write_pid = messageBusResolve("WriteProcess");

    for (;;) {
      /* send a message */
      messageBusSend(write_pid, "Foo Bar Baz.");
      
      /* sleep */
      usleep(1000*1000);
    }

    return 0;
  }
};

int main(int argc, char *argv[])
{
  pgl::Group group(argc, argv);

  group.addProcess<OpenProcess>("OpenProcess");
  group.addProcess<WriteProcess>("WriteProcess");
  group.addProcess<MessageProcess>("MessageProcess");

  return group.run();
}
