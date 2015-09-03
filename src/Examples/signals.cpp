#include <iostream>
#include <pgl.hpp>
#include <signal.h>

class KillerProcess : public pgl::Process
{
  public:
    int main(int argc, char *argv[])
    {
      while (!processTerminate()) {
        if (messageBusWait() != 1) {
          continue;
        }

        std::string message;
        const pid_t peer_pid = messageBusRecv(-1, message);
        ::kill(peer_pid, SIGTERM);
        PGL_LOG() << "Killed PID " << peer_pid;
      }

      return EXIT_SUCCESS;
    }
};

class KillMeProcess : public pgl::Process
{
  public:
    void signalHandler(const struct signalfd_siginfo& ssi)
    {
      PGL_LOG() << "Killed by #" << ssi.ssi_signo;
      setProcessTerminate(EXIT_SUCCESS);
      return;
    }

    int main(int argc, char *argv[]) {
      const pid_t killer_pid = messageBusResolve("Killer");

      while (!processTerminate()) {
        std::string message = "Kill me!";

        messageBusSend(killer_pid, message);
        PGL_LOG() << "Message sent";
        messageBusWait();
        PGL_LOG() << "Bus wait returned";
      }

      PGL_LOG() << "Exiting";

      return EXIT_SUCCESS;
    }
};

int main(int argc, char *argv[])
{
  pgl::Group group(argc, argv);

  group.addProcess<KillerProcess>("Killer");
  group.addProcess<KillMeProcess>("KillMe");

  return group.run();
}

