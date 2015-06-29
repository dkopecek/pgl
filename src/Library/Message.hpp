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

#include <string>
#include <cstdint>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <type_traits>
#include <memory>

namespace pgl
{
  class Message
  {
  public:
    enum Type {
      M2M,
      M2M_FD,
      BUS_PID_LOOKUP, /**< member request to resolve a process name to it's current pid */
      BUS_PID_FORGET, /**< member request to forget that it asked about a pid */
      BUS_HEARTBEAT /**< member heartbeat */
    };

    struct Header
    {
      pid_t pid_from; /**< Source PID */
      pid_t pid_to; /**< Destination PID */
      size_t size; /**< Message size (not including the size of the header) */
      uint8_t hbp; /**< Hash byte position */
      uint8_t hbv; /**< Hash byte value */
      Type type; /**< Type of the message. 0 means member-to-member. Other values are used for master-to-member control message */
      uint8_t data[0]; /**< Pointer to the data part of the message */
    };

    Message(size_t data_size);
    Message(const Header& header);
    Message(Message&& rhs);
    Message& operator=(Message&& rhs);
    Message(const Message&) = delete;
    Message& operator=(const Message&) = delete;
    ~Message();

    void setFrom(pid_t pid);
    pid_t getFrom() const;
    void setTo(pid_t pid);
    pid_t getTo() const;
    void setType(Type type);
    Type getType() const;
    void finalize();
    void validate();

    void copyToData(const std::string& strval);
    void copyFromData(std::string& strval) const;

    template<typename T>
    void copyToData(const T& copyable)
    {
#if __GNUC__ >= 5
      static_assert(std::is_trivially_copyable<T>::value == true,
		    "type is not trivially copyable");
#endif
      const size_t size = sizeof(T);

      if (size != _header_ptr->size) {
	throw std::runtime_error("size mismatch");
      }

      const void *ptr = static_cast<const void *>(&copyable);

      copyToData(ptr, size);
      return;
    }
 
    template<typename T>
    void copyFromData(T& copyable) const
    {
#if __GNUC__ >= 5
      static_assert(std::is_trivially_copyable<T>::value == true,
		    "type is not trivially copyable");
#endif
      const size_t size = sizeof(T);

      if (size != _header_ptr->size) {
	throw std::runtime_error("size mismatch");
      }

      void *ptr = static_cast<void *>(&copyable);

      copyFromData(ptr, size);
      return;
    }

    void copyToData(const void *ptr, size_t size);
    void copyFromData(void *ptr, size_t size) const;

    const uint8_t *buffer() const
    {
      if (!_finalized) {
	throw std::runtime_error("Cannot access message buffer of an incomplete message");
      }
      return _buffer.get();
    }

    uint8_t *bufferWritable()
    {
      return _buffer.get();
    }

    size_t bufferSize() const
    {
      return _buffer_size;
    }

    const uint8_t *data() const
    {
      return reinterpret_cast<const uint8_t*>(_data_ptr);
    }
    
    uint8_t *dataWritable()
    {
      return reinterpret_cast<uint8_t*>(_data_ptr);
    }

    size_t dataSize() const
    {
      return _data_size;
    }

  private:
    std::unique_ptr<uint8_t> _buffer; /**< Memory buffer that holds the whole message (header + data) */
    size_t _buffer_size; /**< Size of the memory buffer */
    Header *_header_ptr; /**< Pointer to the message header */
    void *_data_ptr; /**< Pointer to the data part of the message */
    size_t _data_size; /**< Size of the data part of the message */
    int _fd; /**< Send this file descriptor along with the message, if it doesn't equal -1 */
    bool _finalized; /**< Indicator of the state of hash byte value computation or verification */
  };
} /* namespace pgl */
