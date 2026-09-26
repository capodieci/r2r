// R2R relay -- starts an inbound session without exposing the templates.
//
// HttpSession<Stream> drags in the whole Beast HTTP, WebSocket and TLS stack.
// Instantiating both variants in one translation unit needs more than 2 GB of
// compiler memory, which OOM-kills the build on the size of VPS these relays
// run on. Each variant therefore gets its own .cpp, and listener.cpp -- which
// only needs to hand off a socket -- includes neither.
#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

#include "http_routes.hpp"

namespace r2r {

void start_plain_session(boost::asio::ip::tcp::socket socket, ServerContext& ctx);
void start_tls_session(boost::asio::ip::tcp::socket socket, ServerContext& ctx,
                       boost::asio::ssl::context& tls);

}  // namespace r2r
