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
#include "Utility.hpp"
#include "Timeout.hpp"
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdexcept>

namespace pgl
{
  void closeAllFDs(int from_fd)
  { 
    int fd_max = 1024;
    struct rlimit limit;

    if (getrlimit(RLIMIT_NOFILE, &limit) == 0) {
      fd_max = limit.rlim_cur - 1;
    }

    for (int fd = from_fd; fd <= fd_max; ++fd) {
      close(fd);
    }

    return;
  }

  static const uint8_t zero_byte = 0;

  int writeFD(int bus_fd, int fd, unsigned int max_delay_usec)
  {
    Timeout timeout(max_delay_usec);

    /* Intialize the message header structure */
    struct msghdr hdr;
    memset(&hdr, 0, sizeof hdr);

    /* Setup the control message data with the fd */
    uint8_t cmsg_data[CMSG_SPACE(sizeof(int))];
    memset(cmsg_data, 0, sizeof cmsg_data);

    hdr.msg_control = cmsg_data;
    hdr.msg_controllen = sizeof cmsg_data;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    /* Setup the message header */
    struct iovec iov = { (void *)&zero_byte, sizeof zero_byte };
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_controllen = cmsg->cmsg_len;

    /* Loop until sent or timeout */
    while(true) {
      const ssize_t ret = sendmsg(bus_fd, &hdr, 0);

      if (ret != -1) {
        /* The message was successfully sent */
        return 0;
      }
      else {
        /*
         * An error happend, no data was sent. If the error is only
         * a temporary one and there's still time left, we try again.
         */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          if (timeout) {
            throw BusError(/*recoverable=*/true);
          }
          else {
            // XXX add a sleep here */
            continue;
          }
        }
        else {
          throw BusError(/*recoverable=*/false);
        }
      }
    }
    return -1;
  }

  int readFD(int bus_fd, unsigned int max_delay_usec)
  {
    Timeout timeout(max_delay_usec);
    uint8_t zero = 0xff;
    struct iovec iov = { &zero, 1 };

    struct msghdr hdr;
    memset(&hdr, 0, sizeof hdr);

    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;

    uint8_t cmsg_data[CMSG_SPACE(sizeof(int))];
    memset(&cmsg_data, 0, sizeof cmsg_data);

    hdr.msg_control = cmsg_data;
    hdr.msg_controllen = sizeof cmsg_data;

    while(true) {
      const ssize_t ret = recvmsg(bus_fd, &hdr, 0);

      if (ret != -1) {
        /* message received */
        break;
      }
      else {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          if (timeout) {
            throw BusError(/*recoverable=*/true);
          }
          else {
            /* There's still time, try again */
            // XXX: add a speel here */
            continue;
          }
        }
        else {
          throw BusError(/*recoverable=*/false);
        }
      }
    }

    const struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);

    if (cmsg == nullptr) {
      /* Error: excepted to receive control data in the message */
      throw BusError(/*recoverable=*/false);
    }
    if (cmsg->cmsg_type != SCM_RIGHTS) {
      /* Error: invalid control data type */
      throw BusError(/*recoverable=*/false);
    }

    /* XXX: check cmsg data length */

    int fd = -1;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof fd);

    return fd;
  }
} /* namespace pgl */
