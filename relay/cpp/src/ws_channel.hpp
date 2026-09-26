// R2R relay -- WebSocket read/write pump, templated over the underlying stream.
//
// Instantiated twice:
//   WsChannel<beast::tcp_stream>                   -> ws://  (port 8787)
//   WsChannel<beast::ssl_stream<beast::tcp_stream>> -> wss:// (port 8788)
//
// Every channel owns a strand, so handlers for one connection never run
// concurrently and the Hub can push frames from any thread.
#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include <chrono>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "connection.hpp"
#include "crypto.hpp"
#include "log.hpp"
#include "util.hpp"

namespace r2r {

namespace beast = boost::beast;
namespace net = boost::asio;
namespace websocket = boost::beast::websocket;

template <class Stream>
class WsChannel final : public Connection,
                        public std::enable_shared_from_this<WsChannel<Stream>> {
public:
    using ws_type = websocket::stream<Stream>;

    WsChannel(ws_type ws, ChannelSink& sink, ConnKind kind, bool secure,
              std::string dialled_address, std::size_t max_frame, std::size_t max_queue)
        : ws_(std::move(ws)),
          sink_(sink),
          kind_(kind),
          secure_(secure),
          dialled_address_(std::move(dialled_address)),
          max_frame_(max_frame),
          max_queue_(max_queue),
          id_(util::hex_encode(crypto::random_bytes(6))) {}

    // Call once the WebSocket handshake has completed (client side).
    void start() {
        auto self = shared();
        net::post(ws_.get_executor(), [self] {
            self->apply_options();
            self->do_start();
        });
    }

    // Server side: completes the upgrade for an already-parsed request.
    // `echo_subprotocol`, when non-empty, is sent back in the 101 response.
    template <class Body, class Fields>
    void accept(boost::beast::http::request<Body, Fields> req, std::string echo_subprotocol) {
        apply_options();
        ws_.set_option(websocket::stream_base::decorator(
            [proto = std::move(echo_subprotocol)](websocket::response_type& res) {
                res.set(boost::beast::http::field::server, "r2r-relay/" R2R_VERSION);
                if (!proto.empty())
                    res.set(boost::beast::http::field::sec_websocket_protocol, proto);
            }));
        auto self = shared();
        ws_.async_accept(req, [self](beast::error_code ec) {
            if (ec) {
                log::debug("websocket upgrade failed: ", ec.message());
                return;
            }
            self->do_start();
        });
    }

    // ---- Connection ------------------------------------------------------
    void send_text(std::string msg) override {
        auto self = shared();
        net::post(ws_.get_executor(), [self, m = std::move(msg)]() mutable {
            self->enqueue(std::move(m));
        });
    }

    void close_now(std::uint16_t code, std::string reason) override {
        auto self = shared();
        net::post(ws_.get_executor(), [self, code, reason = std::move(reason)]() mutable {
            if (self->closing_) return;
            self->closing_ = true;
            if (self->writing_) {
                self->pending_close_ = {code, std::move(reason)};
                return;
            }
            self->do_close(code, reason);
        });
    }

    const std::string& id() const noexcept override { return id_; }
    bool secure() const noexcept override { return secure_; }
    ConnKind kind() const noexcept override { return kind_; }
    const std::string& dialled_address() const noexcept override { return dialled_address_; }
    std::size_t queue_depth() const noexcept override { return queue_bytes_; }

private:
    std::shared_ptr<WsChannel> shared() { return this->shared_from_this(); }

    void apply_options() {
        ws_.text(true);
        ws_.read_message_max(max_frame_);
        ws_.auto_fragment(true);

        auto opt = websocket::stream_base::timeout::suggested(
            kind_ == ConnKind::outbound_peer ? beast::role_type::client : beast::role_type::server);
        opt.keep_alive_pings = true;
        opt.idle_timeout = std::chrono::seconds(180);
        ws_.set_option(opt);
    }

    void do_start() {
        opened_ = true;
        sink_.on_open(shared());
        do_read();
    }

    void do_read() {
        ws_.async_read(buffer_, beast::bind_front_handler(&WsChannel::on_read, shared()));
    }

    void on_read(beast::error_code ec, std::size_t) {
        if (ec) return finish(ec);
        if (!ws_.got_text()) {
            // The R2R wire protocol is JSON text; binary payloads travel
            // base64-encoded inside it.
            buffer_.consume(buffer_.size());
            close_now(static_cast<std::uint16_t>(websocket::close_code::unknown_data),
                      "text frames only");
            return;
        }
        std::string msg = beast::buffers_to_string(buffer_.data());
        buffer_.consume(buffer_.size());

        sink_.on_text(shared(), std::move(msg));
        if (!closing_) do_read();
    }

    void enqueue(std::string msg) {
        if (closing_) return;
        if (queue_.size() >= max_queue_) {
            log::warn("connection ", id_, " exceeded its send queue; dropping it");
            closing_ = true;
            if (!writing_)
                do_close(static_cast<std::uint16_t>(websocket::close_code::try_again_later),
                         "send queue overflow");
            return;
        }
        queue_bytes_ += msg.size();
        queue_.push_back(std::move(msg));
        if (!writing_) do_write();
    }

    void do_write() {
        writing_ = true;
        ws_.text(true);
        ws_.async_write(net::buffer(queue_.front()),
                        beast::bind_front_handler(&WsChannel::on_write, shared()));
    }

    void on_write(beast::error_code ec, std::size_t) {
        writing_ = false;
        if (ec) return finish(ec);
        queue_bytes_ -= queue_.front().size();
        queue_.pop_front();
        if (!queue_.empty() && !closing_) {
            do_write();
            return;
        }
        if (pending_close_) {
            auto [code, reason] = *pending_close_;
            pending_close_.reset();
            do_close(code, reason);
        }
    }

    void do_close(std::uint16_t code, const std::string& reason) {
        websocket::close_reason cr(static_cast<websocket::close_code>(code));
        cr.reason = reason.substr(0, 120).c_str();
        auto self = shared();
        ws_.async_close(cr, [self](beast::error_code ec) { self->finish(ec); });
    }

    void finish(beast::error_code ec) {
        if (finished_) return;
        finished_ = true;
        if (ec && ec != websocket::error::closed && ec != net::error::operation_aborted &&
            ec != net::error::eof)
            log::debug("connection ", id_, " ended: ", ec.message());

        beast::error_code ignored;
        beast::get_lowest_layer(ws_).socket().shutdown(net::ip::tcp::socket::shutdown_both, ignored);
        beast::get_lowest_layer(ws_).socket().close(ignored);

        queue_.clear();
        queue_bytes_ = 0;
        if (opened_) sink_.on_close(shared());
    }

    ws_type ws_;
    ChannelSink& sink_;
    ConnKind kind_;
    bool secure_;
    std::string dialled_address_;
    std::size_t max_frame_;
    std::size_t max_queue_;
    std::string id_;

    beast::flat_buffer buffer_;
    std::deque<std::string> queue_;
    std::size_t queue_bytes_{0};
    bool writing_{false};
    bool closing_{false};
    bool finished_{false};
    bool opened_{false};
    std::optional<std::pair<std::uint16_t, std::string>> pending_close_;
};

using PlainStream = beast::tcp_stream;
using TlsStream = beast::ssl_stream<beast::tcp_stream>;
using PlainChannel = WsChannel<PlainStream>;
using TlsChannel = WsChannel<TlsStream>;

}  // namespace r2r
