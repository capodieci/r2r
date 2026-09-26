#include "listener.hpp"

#include <unistd.h>

#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>

#include <cerrno>
#include <cstring>

#include "log.hpp"
#include "session_factory.hpp"
#include "util.hpp"

namespace r2r {

using tcp = net::ip::tcp;

Listener::Listener(net::io_context& ioc, ServerContext& ctx, ssl::context* tls_ctx,
                   std::string label)
    : ioc_(ioc), ctx_(ctx), tls_ctx_(tls_ctx), label_(std::move(label)), acceptor_(ioc) {}

bool Listener::open(const std::string& bind_addr, std::uint16_t port) {
    boost::system::error_code ec;
    auto address = net::ip::make_address(bind_addr, ec);
    if (ec) {
        log::error(label_, ": '", bind_addr, "' is not a valid bind address");
        return false;
    }
    const tcp::endpoint endpoint{address, port};

    acceptor_.open(endpoint.protocol(), ec);
    if (ec) {
        log::error(label_, ": cannot open socket: ", ec.message());
        return false;
    }
    acceptor_.set_option(net::socket_base::reuse_address(true), ec);
    if (ec) log::warn(label_, ": SO_REUSEADDR could not be set: ", ec.message());

    acceptor_.bind(endpoint, ec);
    if (ec) {
        log::error(label_, ": cannot bind ", bind_addr, ":", port, ": ", ec.message(),
                   ec == boost::system::errc::permission_denied
                       ? " (ports below 1024 need CAP_NET_BIND_SERVICE)"
                       : "");
        return false;
    }
    acceptor_.listen(net::socket_base::max_listen_connections, ec);
    if (ec) {
        log::error(label_, ": cannot listen: ", ec.message());
        return false;
    }
    log::info(label_, " listening on ", util::format_address(bind_addr, port));
    return true;
}

void Listener::run() { do_accept(); }

void Listener::stop() {
    stopped_ = true;
    boost::system::error_code ec;
    acceptor_.close(ec);
}

void Listener::do_accept() {
    if (stopped_) return;
    // Each connection gets its own strand, so its handlers never overlap.
    acceptor_.async_accept(
        net::make_strand(ioc_),
        boost::beast::bind_front_handler(&Listener::on_accept, shared_from_this()));
}

void Listener::on_accept(boost::system::error_code ec, tcp::socket socket) {
    if (stopped_) return;
    if (ec) {
        if (ec == net::error::operation_aborted) return;
        // Out of descriptors or a transient kernel error: keep the acceptor
        // alive rather than losing the port.
        log::warn(label_, ": accept failed: ", ec.message());
        do_accept();
        return;
    }

    if (tls_ctx_)
        start_tls_session(std::move(socket), ctx_, *tls_ctx_);
    else
        start_plain_session(std::move(socket), ctx_);

    do_accept();
}

namespace {

// "Not found" and "not allowed to read" are different problems with different
// fixes, and reporting the second as the first sends an operator hunting for a
// file that is sitting exactly where they put it.
std::string readability_problem(const std::string& path) {
    if (::access(path.c_str(), R_OK) == 0) return {};
    switch (errno) {
        case ENOENT: return "does not exist";
        case EACCES: return "exists but this process may not read it";
        default: return std::strerror(errno);
    }
}

}  // namespace

bool reload_tls_context(ssl::context& ctx, const Config& cfg) {
    boost::system::error_code ec;
    ctx.use_certificate_chain_file(cfg.tls_cert, ec);
    if (ec) {
        log::error("cannot load certificate ", cfg.tls_cert, ": ", ec.message());
        return false;
    }
    ctx.use_private_key_file(cfg.tls_key, ssl::context::pem, ec);
    if (ec) {
        log::error("cannot load private key ", cfg.tls_key, ": ", ec.message());
        return false;
    }
    return true;
}

std::unique_ptr<ssl::context> make_tls_context(const Config& cfg) {
    const std::string cert_problem = readability_problem(cfg.tls_cert);
    const std::string key_problem = readability_problem(cfg.tls_key);
    if (!cert_problem.empty() || !key_problem.empty()) {
        if (!cert_problem.empty())
            log::warn("TLS certificate ", cfg.tls_cert, " ", cert_problem);
        if (!key_problem.empty())
            log::warn("TLS private key ", cfg.tls_key, " ", key_problem);
        log::warn("the wss:// listener will not start; ws:// is unaffected. "
                  "Running as uid ", ::getuid(), " gid ", ::getgid());
        if (cert_problem.find("may not read") != std::string::npos ||
            key_problem.find("may not read") != std::string::npos)
            log::warn("this is a permissions problem, not a missing file. The key is meant to "
                      "stay unreadable to everyone but the relay's own user, so nothing needs "
                      "moving or copying: start the relay through systemd, or for a hand-run "
                      "test pass --cert and --key pointing at files this user can read.");
        return nullptr;
    }

    auto ctx = std::make_unique<ssl::context>(ssl::context::tls_server);
    boost::system::error_code ec;

    ctx->set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                         ssl::context::no_sslv3 | ssl::context::no_tlsv1 |
                         ssl::context::no_tlsv1_1 | ssl::context::single_dh_use,
                     ec);
    if (ec) {
        log::error("cannot set TLS options: ", ec.message());
        return nullptr;
    }

    if (!reload_tls_context(*ctx, cfg)) return nullptr;

    // Modern ciphers only; the relay has no legacy clients to appease.
    SSL_CTX_set_min_proto_version(ctx->native_handle(), TLS1_2_VERSION);
    if (SSL_CTX_set_ciphersuites(ctx->native_handle(),
                                 "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
                                 "TLS_AES_128_GCM_SHA256") != 1)
        log::warn("could not restrict the TLS 1.3 cipher suites");
    if (SSL_CTX_set_cipher_list(ctx->native_handle(),
                                "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS") != 1)
        log::warn("could not restrict the TLS 1.2 cipher list");
    SSL_CTX_set_options(ctx->native_handle(), SSL_OP_CIPHER_SERVER_PREFERENCE);

    log::info("TLS enabled using ", cfg.tls_cert);
    return ctx;
}

}  // namespace r2r
