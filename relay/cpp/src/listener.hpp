// R2R relay -- TCP acceptor. One instance per port.
#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

#include <cstdint>
#include <memory>
#include <string>

#include "http_routes.hpp"

namespace r2r {

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;

class Listener : public std::enable_shared_from_this<Listener> {
public:
    // `tls_ctx` selects the protocol served on this port: nullptr -> ws://,
    // otherwise wss://. Both hand the resulting session the same ServerContext.
    Listener(net::io_context& ioc, ServerContext& ctx, ssl::context* tls_ctx, std::string label);

    bool open(const std::string& bind_addr, std::uint16_t port);
    void run();
    void stop();

private:
    void do_accept();
    void on_accept(boost::system::error_code ec, net::ip::tcp::socket socket);

    net::io_context& ioc_;
    ServerContext& ctx_;
    ssl::context* tls_ctx_;
    std::string label_;
    net::ip::tcp::acceptor acceptor_;
    bool stopped_{false};
};

// Builds a TLS server context from the configured certificate and key.
// Returns nullptr (and logs) if either file is missing or unusable.
std::unique_ptr<ssl::context> make_tls_context(const Config& cfg);

// Reloads the certificate and key into a context that is already serving.
// Connections already established keep the material they negotiated with;
// everything opened afterwards gets the new certificate. This is what makes an
// automated renewal survivable without dropping every peer link.
bool reload_tls_context(ssl::context& ctx, const Config& cfg);

}  // namespace r2r
