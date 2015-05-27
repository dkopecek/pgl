#include <iostream>
#include <unistd.h>
#include <cstdint>
#include <fstream>
#include "Group.hpp"

class EchoProcess : public pgl::Process
{
public:
  int main(int argc, char *argv[])
  {
    for (;;) {
      if (messageBusWait() != 1) {
	continue;
      }

      std::string message;
      const pid_t peer_pid = messageBusRecv(-1, message);
      messageBusSend(peer_pid, message);
    }
    return 0;
  }
};

class PingProcess : public pgl::Process
{
public:
  int main(int argc, char *argv[])
  {
    const pid_t peer_pid = messageBusResolve("EchoProcess");

    for (;;) {
      std::string reply;
      messageBusSendRecv(peer_pid, "ping", reply);
      if (reply != "ping") {
	throw std::runtime_error("invalid reply");
      }
      //usleep(1000);
    }

    return 0;
  }
};

int main(int argc, char *argv[])
{
  pgl::Group group(argc, argv);

  group.addProcess<EchoProcess>("EchoProcess");
  group.addProcess<PingProcess>("PingProcess1");
  group.addProcess<PingProcess>("PingProcess2");

  return group.run();
}
