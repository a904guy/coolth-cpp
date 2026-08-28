#include "net.h"

#ifdef _WIN32
#include <winsock2.h>
// Second: ws2tcpip.h needs winsock2.h before it.
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <cerrno>
#include <cstring>
#include <set>

#include "../components/coolth/discovery.h"

namespace coolth_cli {
namespace {

#ifdef _WIN32
// Winsock has to be started before any other call into it. A function-local
// static gets that done once, on whichever call comes first.
bool winsock_ready() {
  static const bool ready = [] {
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }();
  return ready;
}

using RawSocket = SOCKET;
using SockLen = int;
using IoSize = int;
constexpr RawSocket kRawInvalid = INVALID_SOCKET;

// Winsock takes a DWORD of milliseconds where POSIX takes a struct timeval.
void set_timeouts(RawSocket socket, int seconds, bool send_too) {
  const DWORD milliseconds = static_cast<DWORD>(seconds) * 1000;
  setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
             reinterpret_cast<const char *>(&milliseconds), sizeof(milliseconds));
  if (send_too)
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char *>(&milliseconds),
               sizeof(milliseconds));
}

void close_socket(RawSocket socket) { closesocket(socket); }
#else
bool winsock_ready() { return true; }

using RawSocket = int;
using SockLen = socklen_t;
using IoSize = ssize_t;
constexpr RawSocket kRawInvalid = -1;

void set_timeouts(RawSocket socket, int seconds, bool send_too) {
  struct timeval timeout {seconds, 0};
  setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  if (send_too)
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

void close_socket(RawSocket socket) { ::close(socket); }
#endif

// setsockopt's value is a void * on POSIX and a const char * on Windows.
void set_flag(RawSocket socket, int level, int option) {
  const int one = 1;
  setsockopt(socket, level, option, reinterpret_cast<const char *>(&one),
             sizeof(one));
}

}  // namespace

bool tcp_connect(const std::string &host, uint16_t port, int timeout_seconds,
                 Socket *handle, coolth::Connection *connection) {
  if (!winsock_ready())
    return false;

  struct addrinfo hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *result = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0 ||
      result == nullptr)
    return false;

  const RawSocket fd = ::socket(result->ai_family, result->ai_socktype,
                                result->ai_protocol);
  if (fd == kRawInvalid) {
    freeaddrinfo(result);
    return false;
  }
  set_timeouts(fd, timeout_seconds, true);
  set_flag(fd, IPPROTO_TCP, TCP_NODELAY);

  const int rc = ::connect(fd, result->ai_addr,
                           static_cast<SockLen>(result->ai_addrlen));
  freeaddrinfo(result);
  if (rc != 0) {
    close_socket(fd);
    return false;
  }

  *handle = static_cast<Socket>(fd);
  connection->write = [fd](const coolth::Bytes &data) {
    size_t sent = 0;
    while (sent < data.size()) {
      const IoSize n =
          ::send(fd, reinterpret_cast<const char *>(data.data()) + sent,
                 static_cast<int>(data.size() - sent), 0);
      if (n <= 0)
        return false;
      sent += static_cast<size_t>(n);
    }
    return true;
  };
  connection->read_exact = [fd](size_t length, coolth::Bytes *out) {
    out->assign(length, 0);
    size_t got = 0;
    while (got < length) {
      const IoSize n = ::recv(fd, reinterpret_cast<char *>(out->data()) + got,
                              static_cast<int>(length - got), 0);
      if (n <= 0)
        return false;
      got += static_cast<size_t>(n);
    }
    return true;
  };
  return true;
}

void tcp_close(Socket handle) {
  if (handle != kInvalidSocket)
    close_socket(static_cast<RawSocket>(handle));
}

bool discover(int seconds,
              const std::function<void(const std::string &,
                                       const coolth::Bytes &)> &on_device,
              std::string *error) {
  if (!winsock_ready()) {
    *error = "could not start Winsock";
    return false;
  }
  const RawSocket fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == kRawInvalid) {
    *error = "could not open a UDP socket";
    return false;
  }
  set_flag(fd, SOL_SOCKET, SO_BROADCAST);
  set_timeouts(fd, 1, false);

  const coolth::Bytes probe = coolth::discovery_request();
  // Two ports, because different firmware generations listen on different ones.
  for (uint16_t port : {6445, 20086}) {
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_BROADCAST;
    for (int i = 0; i < 3; i++)  // UDP; repeat rather than hope
      ::sendto(fd, reinterpret_cast<const char *>(probe.data()),
               static_cast<int>(probe.size()), 0, (struct sockaddr *) &addr,
               sizeof(addr));
  }

  std::set<std::string> seen;
  for (int elapsed = 0; elapsed < seconds; elapsed++) {
    for (;;) {
      uint8_t buffer[2048];
      struct sockaddr_in from = {};
      SockLen from_len = sizeof(from);
      const IoSize n = ::recvfrom(fd, reinterpret_cast<char *>(buffer),
                                  sizeof(buffer), 0, (struct sockaddr *) &from,
                                  &from_len);
      if (n <= 0)
        break;  // timed out for this second
      char ip[INET_ADDRSTRLEN] = {};
      if (inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip)) == nullptr)
        continue;
      if (!seen.insert(ip).second)
        continue;
      on_device(ip, coolth::Bytes(buffer, buffer + n));
    }
  }
  close_socket(fd);
  return true;
}

}  // namespace coolth_cli
