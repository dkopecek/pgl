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
#include <grp.h>
#include <sys/stat.h>

static void shared_postExecSetup()
{
  /*
   * Get uid/gid of the user nobody before we chroot
   */
  struct passwd *pw = getpwnam("nobody");
  if (pw == nullptr) {
    throw std::runtime_error("cannot setuid to nobody");
  }

  /*
   * Chroot to an empty directory
   */
  char chroot_dir[] = "/tmp/minprivs-XXXXXX";
  if (mkdtemp(chroot_dir) == nullptr) {
    throw std::runtime_error("cannot create a unique chroot directory");
  }
  if (chdir(chroot_dir) != 0 ||
      chroot(chroot_dir) != 0) {
    throw std::runtime_error("cannot chroot/chdir");
  }

#if !defined(DROP_CAPABILITIES)
  /*
   * Drop root. Run as user "nobody".
   */
  if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
      setgid(pw->pw_gid) != 0 ||
      setuid(pw->pw_uid) != 0) {
    throw std::runtime_error("cannot switch to user nobody");    
  }
#endif
#if defined(DROP_CAPABILITIES)
  /*
   * Drop capabilities
   */
  capng_clear(CAPNG_SELECT_BOTH);
  if (capng_apply(CAPNG_SELECT_BOTH) != 0) {
    throw std::runtime_error("cannot drop capabilities");
  }
#endif

  /*
   * Setup seccomp whitelist. Only read() from fd 0 and write to fd 1 is
   * required for the pgl API to work in a pgl::Process.
   */
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0); //, SCMP_A0(SCMP_CMP_EQ, 0));
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
  if (seccomp_load(ctx) != 0) {
    throw std::runtime_error("cannot setup seccomp whitelist");
  }
  seccomp_release(ctx);

  return;
}

class EchoProcess : public pgl::Process
{
public:
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
