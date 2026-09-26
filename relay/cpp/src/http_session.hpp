// R2R relay -- one inbound connection, before we know what it wants.
//
// Reads an HTTP request and then either upgrades it to a WebSocket (handing a
// WsChannel to the Hub) or answers it as plain HTTP. Instantiated for both
// stream types, so port 8787 and port 8788 run identical logic.
#pragma once

#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

#include "http_routes.hpp"
#include "log.hpp"
#include "protocol.hpp"
#include "util.hpp"
#include "ws_channel.hpp"

namespace r2r {

template <class Stream>
class HttpSession final : public std::enable_shared_from_this<HttpSession<Stream>> {
public:
    static constexpr bool kTls = std::is_same_v<Stream, TlsStream>;
    using tcp = boost::asio::ip::tcp;

    template <class... StreamArgs>
    HttpSession(tcp::socket&& socket, ServerContext& ctx, StreamArgs&&... args)
        : stream_(std::move(socket), std::forward<StreamArgs>(args)...), ctx_(ctx) {}

    void run() {
        auto self = this->shared_from_this();
        net::dispatch(beast::get_lowest_layer(stream_).get_executor(),
                      [self] { self->on_run(); });
    }

private:
    void on_run() {
        if constexpr (kTls) {
            beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
            auto self = this->shared_from_this();
            stream_.async_handshake(boost::asio::ssl::stream_base::server,
                                    [self](beast::error_code ec) {
                                        if (ec) {
                                            log::debug("tls handshake failed: ", ec.message());
                                            return;
                                        }
                                        self->do_read();
                                    });
        } else {
            do_read();
        }
    }

    void do_read() {
        parser_.emplace();
        // Beast compares Content-Length against this while parsing the header,
        // so it has to start at the largest a route could legitimately accept.
        // Anything not entitled to that much is rejected in on_read_header.
        parser_->body_limit(ctx_.cfg.max_blob_bytes + 8192);
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
        auto self = this->shared_from_this();
        // Headers first: the body limit depends on the route, because a voice
        // or video upload is orders of magnitude larger than anything else the
        // relay accepts.
        http::async_read_header(stream_, buffer_, *parser_,
                                [self](beast::error_code ec, std::size_t) {
                                    self->on_read_header(ec);
                                });
    }

    void on_read_header(beast::error_code ec) {
        if (ec == http::error::end_of_stream) return do_close();
        // A Content-Length past the ceiling is rejected while the header is
        // parsed. Say so rather than dropping the connection on the floor.
        if (ec == http::error::body_limit) return reject_oversized();
        if (ec) {
            if (ec != beast::error::timeout) log::debug("http header read failed: ", ec.message());
            return do_close();
        }

        const auto& head = parser_->get();
        if (boost::beast::websocket::is_upgrade(head)) return on_read({});

        const std::string target(head.target());
        const bool upload = head.method() == http::verb::post && util::starts_with(target, "/blob");
        if (upload) {
            // A large upload over a slow link needs longer than a normal request.
            beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(120));
        } else {
            const auto declared = parser_->content_length();
            if (declared && *declared > kMaxRequestBody) return reject_oversized();
        }
        upload_ = upload;

        if (parser_->is_done()) return on_read({});

        auto self = this->shared_from_this();
        http::async_read(stream_, buffer_, *parser_,
                         [self](beast::error_code ec2, std::size_t) { self->on_read(ec2); });
    }

    void on_read(beast::error_code ec) {
        if (ec == http::error::end_of_stream) return do_close();
        if (ec == http::error::body_limit) return reject_oversized();
        if (ec) {
            if (ec != beast::error::timeout) log::debug("http read failed: ", ec.message());
            return do_close();
        }

        auto req = parser_->release();

        // Catches a chunked body that declared no length up front.
        if (!upload_ && req.body().size() > kMaxRequestBody) return reject_oversized();

        if (boost::beast::websocket::is_upgrade(req)) {
            // Beast's WebSocket timeout policy takes over from here.
            beast::get_lowest_layer(stream_).expires_never();

            std::string echo;
            auto it = req.find(http::field::sec_websocket_protocol);
            if (it != req.end()) {
                const std::string requested(it->value());
                if (requested.find(proto::kSubprotocol) != std::string::npos)
                    echo = proto::kSubprotocol;
            }

            auto channel = std::make_shared<WsChannel<Stream>>(
                boost::beast::websocket::stream<Stream>(std::move(stream_)), ctx_.hub,
                ConnKind::inbound, kTls, std::string{}, ctx_.cfg.max_frame_bytes,
                ctx_.cfg.max_send_queue);
            channel->accept(std::move(req), std::move(echo));
            return;  // the channel owns the stream now
        }

        // Same guard as the WebSocket path: a request body or X-R2R-Auth
        // header with a wrong-typed field must cost a 400, not the process.
        http::response<http::string_body> response;
        try {
            response = handle_http_request(req, ctx_, kTls);
        } catch (const std::exception& e) {
            const bool typed = dynamic_cast<const nlohmann::json::exception*>(&e) != nullptr;
            if (!typed) log::warn("http request failed: ", e.what());
            response = http::response<http::string_body>{
                typed ? http::status::bad_request : http::status::internal_server_error,
                req.version()};
            response.set(http::field::server, "r2r-relay/" R2R_VERSION);
            response.set(http::field::content_type, "application/json");
            response.set(http::field::cache_control, "no-store");
            response.body() = typed ? "{\"ok\":false,\"error\":\"bad_field\"}\n"
                                    : "{\"ok\":false,\"error\":\"internal\"}\n";
            response.keep_alive(req.keep_alive());
            response.prepare_payload();
        }
        const bool keep_alive = response.keep_alive();
        auto held = std::make_shared<http::response<http::string_body>>(std::move(response));
        auto self = this->shared_from_this();
        http::async_write(stream_, *held,
                          [self, held, keep_alive](beast::error_code ec2, std::size_t) {
                              if (ec2 || !keep_alive) return self->do_close();
                              self->do_read();
                          });
    }

    void reject_oversized() {
        http::response<http::string_body> res{http::status::payload_too_large, 11};
        res.set(http::field::server, "r2r-relay/" R2R_VERSION);
        res.set(http::field::content_type, "application/json");
        res.body() = "{\"ok\":false,\"error\":\"too_big\"}\n";
        res.keep_alive(false);
        res.prepare_payload();
        auto held = std::make_shared<http::response<http::string_body>>(std::move(res));
        auto self = this->shared_from_this();
        http::async_write(stream_, *held,
                          [self, held](beast::error_code, std::size_t) { self->do_close(); });
    }

    void do_close() {
        beast::error_code ec;
        if constexpr (kTls) {
            beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(5));
            auto self = this->shared_from_this();
            stream_.async_shutdown([self](beast::error_code) {
                beast::error_code ignored;
                beast::get_lowest_layer(self->stream_)
                    .socket()
                    .shutdown(tcp::socket::shutdown_both, ignored);
            });
        } else {
            stream_.socket().shutdown(tcp::socket::shutdown_both, ec);
        }
    }

    static constexpr std::uint64_t kMaxRequestBody = 64 * 1024;

    Stream stream_;
    ServerContext& ctx_;
    beast::flat_buffer buffer_;
    std::optional<http::request_parser<http::string_body>> parser_;
    bool upload_{false};
};

using PlainHttpSession = HttpSession<PlainStream>;
using TlsHttpSession = HttpSession<TlsStream>;

}  // namespace r2r
