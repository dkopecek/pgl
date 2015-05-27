#include "Group.hpp"

#include <iostream>
#include <unistd.h>
#include <cstdint>
#include <fstream>
#include <sys/types.h>
#include <unistd.h>
#include <cap-ng.h>
#include <seccomp.h>
#include <pwd.h>

static void shared_preExecSetup()
{
  /*
   * run as user "nobody"
   */
  struct passwd *pw = getpwnam("nobody");
  if (pw == nullptr) {
    throw std::runtime_error("cannot setuid to nobody");
  }
  setuid(pw->pw_uid);
  setgid(pw->pw_gid);

  /*
   * Drop capabilities
   */
  capng_clear(CAPNG_SELECT_BOTH);
  capng_apply(CAPNG_SELECT_BOTH);
}

static void shared_postExecSetup()
{
  /*
   * Setup seccomp whitelist. Only read() from fd 0 and write to fd 1 is
   * required for the pgl API to work in a pgl::Process.
   */
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_load(ctx);
  seccomp_release(ctx);
}


class EchoProcess : public pgl::Process
{
public:
  void preExecSetup()
  {
    shared_preExecSetup();
  }

  void postExecSetup()
  {
    shared_postExecSetup();
  }

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
  void preExecSetup()
  {
    shared_preExecSetup();
  }

  void postExecSetup()
  {
    shared_postExecSetup();
  }

  int main(int argc, char *argv[])
  {
    const pid_t peer_pid = messageBusResolve("EchoProcess");

    for (;;) {
      std::string reply;
      messageBusSendRecv(peer_pid, "ping", reply);
      if (reply != "ping") {
	throw std::runtime_error("invalid reply");
      }
      usleep(1000);
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
