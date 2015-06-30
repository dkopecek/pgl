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
#include "Message.hpp"
#include <cstring>

namespace pgl
{
  Message::Message()
  {
    destroy();
  }

  Message::Message(size_t data_size)
    : _buffer_size(sizeof(Message::Header) + data_size),
      _data_size(data_size)
  {
    _buffer = std::unique_ptr<uint8_t>(new uint8_t[_buffer_size]);
    _header_ptr = reinterpret_cast<Message::Header *>(_buffer.get());
    _data_ptr = reinterpret_cast<void *>(_header_ptr->data);

    memset(_header_ptr, 0, sizeof(Message::Header));

    _header_ptr->pid_from = -1;
    _header_ptr->pid_to = -1;
    _header_ptr->size = _data_size;
    _header_ptr->hbp = 0;
    _header_ptr->hbv = 0;
    _header_ptr->type = Type::M2M;

    memset(_data_ptr, 0, _data_size);

    _finalized = false;
    _fd = -1;
    return;
  }

  Message::Message(const Message::Header& header)
    : _buffer_size(sizeof(Message::Header) + header.size),
      _data_size(header.size)
  {
    _buffer = std::unique_ptr<uint8_t>(new uint8_t[_buffer_size]);
    _header_ptr = reinterpret_cast<Message::Header *>(_buffer.get());
    _data_ptr = reinterpret_cast<void *>(_header_ptr->data);

    *_header_ptr = header;
    memset(_data_ptr, 0, _data_size);
    _finalized = false;
    _fd = -1;
    return;
  }

  Message& Message::operator=(Message&& rhs)
  {
    if (this != &rhs) {
      _buffer_size = rhs._buffer_size;
      _data_size = rhs._data_size;
      _buffer = std::move(rhs._buffer);
      _header_ptr = rhs._header_ptr;
      _data_ptr = rhs._data_ptr;
      _finalized = rhs._finalized;
      _fd = rhs._fd;
      rhs.destroy();
    }
    return *this;
  }

  Message::Message(Message&& rhs)
    : _buffer_size(rhs._buffer_size),
      _data_size(rhs._data_size)
  {
    if (this != &rhs) {
      _buffer = std::move(rhs._buffer);
      _header_ptr = rhs._header_ptr;
      _data_ptr = rhs._data_ptr;
      _finalized = rhs._finalized;
      _fd = rhs._fd;
      rhs.destroy();
    }
    return;
  }

  Message::~Message()
  {
    _buffer = nullptr;
    destroy();
  }

  void Message::destructiveCopy(Message& rhs)
  {
    if (this != &rhs) {
      _buffer_size = rhs._buffer_size;
      _data_size = rhs._data_size;
      _buffer = std::move(rhs._buffer);
      _header_ptr = rhs._header_ptr;
      _data_ptr = rhs._data_ptr;
      _finalized = rhs._finalized;
      _fd = rhs._fd;
      rhs.destroy();
    }
  }

  void Message::destroy()
  {
    _buffer_size = 0;
    _header_ptr = nullptr;
    _data_ptr = nullptr;
    _data_size = 0;
    _fd = -1;
    _finalized = false;
    _buffer.release();
  }

  void Message::setFrom(pid_t pid)
  {
    if (_finalized) {
      throw std::runtime_error("setFrom: cannot modify finalized message");
    }
    _header_ptr->pid_from = pid;
    return;
  }

  pid_t Message::getFrom() const
  {
    if (!_finalized) {
      throw std::runtime_error("getFrom: cannot read from an incomplete message");
    }
    return _header_ptr->pid_from;
  }
  
  void Message::setTo(pid_t pid)
  {
    if (_finalized) {
      throw std::runtime_error("setTo: cannot modify finalized message");
    }
    _header_ptr->pid_to = pid;
    return;
  }

  pid_t Message::getTo() const
  {
    if (!_finalized) {
      throw std::runtime_error("getTo: cannot read from an incomplete message");
    }
    return _header_ptr->pid_to;
  }

  void Message::setType(Type type)
  {
    if (_finalized) {
      throw std::runtime_error("setType: cannot modify finalized message");
    }
    _header_ptr->type = type;
    return;
  }

  Message::Type Message::getType() const
  {
    if (!_finalized) {
      throw std::runtime_error("getType: cannot read from an incomplete message");
    }
    return getTypeUnsafe();
  }

  Message::Type Message::getTypeUnsafe() const
  {
    return _header_ptr->type;
  }
  
  void Message::setFD(int fd)
  {
    if (_finalized) {
      throw std::runtime_error("setFD: cannot modify finalized message");
    }
    setFDUnsafe(fd);
    return;
  }

  void Message::setFDUnsafe(int fd)
  {
    _fd = fd;
    return;
  }

  int Message::getFD() const
  {
    if (!_finalized) {
      throw std::runtime_error("getFD: cannot read from an incomplete message");
    }
    return _fd;
  }

  void Message::finalize()
  {
    if (_finalized) {
      throw std::runtime_error("Already finalized");
    }
    _finalized = true;
    /* TODO: fill hbv and hbp */
    return;
  }

  void Message::validate()
  {
    _finalized = true;
    return;
  }

  void Message::copyToData(const std::string& strval)
  {
    if (_finalized) {
      throw std::runtime_error("copyToData: cannot modify finalized message");
    }

    const size_t size = strval.size();

    if (size != _header_ptr->size) {
      throw std::runtime_error("copyToData: size mismatch");
    }

    const void *ptr = reinterpret_cast<const void *>(strval.c_str());

    if (ptr == nullptr) {
      throw std::runtime_error("copyToData: invalid string");
    }

    copyToData(ptr, size);
    return;
  }

  void Message::copyFromData(std::string& strval) const
  {
    if (!_finalized) {
      throw std::runtime_error("copyFromData: cannot copy data from an incomplete message");
    }
    const char *ptr = static_cast<const char *>(_data_ptr);
    strval.assign(ptr, _header_ptr->size);
    return;
  }

  void Message::copyToData(const void *ptr, size_t size)
  {
    if (_finalized) {
      throw std::runtime_error("copyToData: cannot modify finalized message");
    }
    if (ptr == nullptr) {
      throw std::runtime_error("copyToData: invalid arguments");
    }
    if (size != _header_ptr->size) {
      throw std::runtime_error("copyToData: size mismatch");
    }
    memcpy(_data_ptr, ptr, size);
    return;
  }

  void Message::copyFromData(void *ptr, size_t size) const
  {
    if (!_finalized) {
      throw std::runtime_error("copyFromData: cannot copy data from an incomplete message");
    }
    if (ptr == nullptr) {
      throw std::runtime_error("copyFromData: invalid arguments");
    }
    if (size != _header_ptr->size) {
      throw std::runtime_error("copyFromDat: size mismatch");
    }
    memcpy(ptr, _data_ptr, size);
    return;
  }
} /* namespace pgl */
