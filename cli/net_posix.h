// POSIX sockets and an HTTPS client, kept out of the library so it stays
// dependency-free and buildable anywhere. Only the CLI needs these.
#pragma once

#include <string>

#include "../components/coolth/cloud.h"
#include "../components/coolth/lan.h"

namespace coolth_cli {

// Opens a TCP connection and returns a Connection the transport can drive.
// `handle` must be closed with tcp_close.
bool tcp_connect(const std::string &host, uint16_t port, int timeout_seconds,
                 int *handle, coolth::Connection *connection);
void tcp_close(int handle);

// Broadcasts the discovery probe and collects replies for `seconds`.
// Calls `on_device` once per distinct address.
bool discover(int seconds,
              const std::function<void(const std::string &ip,
                                       const coolth::Bytes &response)> &on_device,
              std::string *error);

// An HttpPost backed by libcurl if available, or a plain refusal if not.
coolth::HttpPost make_http_post(std::string *error_out);
bool https_available();

}  // namespace coolth_cli
