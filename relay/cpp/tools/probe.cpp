// r2r-probe -- a small client for exercising a relay.
//
//   r2r-probe status                       counters from /status.json
//   r2r-probe peers                        GET /peers.json
//   r2r-probe ping                         WebSocket round trip
//   r2r-probe claim <uuid>                 burn an invite, print the three new codes
//   r2r-probe send <fingerprint> <text>    leave a payload in the dead drop
//   r2r-probe fetch                        collect and acknowledge waiting payloads
//   r2r-probe onion <fingerprint> <text>   build a sealed multi-hop route
//
// Options: --url ws://host:port (default ws://127.0.0.1:8787), --id <hex>,
//          --hops host:port,host:port, --http http://host:port, --timeout N
//
// Every network operation is asynchronous and bounded by --timeout: Asio's
// synchronous reads poll indefinitely, which would let a silent peer hang the
// probe forever.
//
// The payload written by `send` is not end-to-end encrypted: this is a wire
// protocol probe, not a messaging client. The relay treats it as opaque bytes
// either way.
#include <boost/asio/connect.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "crypto.hpp"
#include "onion.hpp"
#include "peers.hpp"
#include "protocol.hpp"
#include "util.hpp"

namespace beast = boost::beast;
namespace http = boost::beast::http;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace websocket = boost::beast::websocket;
using tcp = boost::asio::ip::tcp;
using nlohmann::json;
using namespace r2r;

namespace {

struct Options {
    std::string url = "ws://127.0.0.1:8787";
    std::string http_url;
    std::string key_path;       // ed25519 seed; identity is derived from it
    std::string path = "/r2r";  // request path for the upgrade
    std::vector<std::string> hops;
    int timeout_s = 15;
    bool anonymous = false;     // --anonymous: hello without proving an identity
};

// A client identity is an ed25519 key, and its fingerprint is a hash of the
// public half. The relay will not bind a mailbox to a fingerprint without a
// signature from the matching key, so the probe needs a real one.
struct Identity {
    crypto::NodeIdentity key;
    std::string fingerprint;
};

std::optional<Identity> load_identity(const std::string& path) {
    auto key = crypto::NodeIdentity::load_or_create(path);
    if (!key) return std::nullopt;
    Identity id{std::move(*key), ""};
    id.fingerprint = crypto::fingerprint(id.key.ed_pub());
    return id;
}

// Adds id/pubkey/ts/nonce/sig to a frame that needs to prove who is sending it.
void sign_frame(json& frame, const Identity& id) {
    const std::int64_t ts = util::now_unix();
    const std::string nonce = util::hex_encode(crypto::random_bytes(12));
    frame["id"] = id.fingerprint;
    frame["pubkey"] = util::b64_encode(id.key.ed_pub());
    frame["ts"] = ts;
    frame["nonce"] = nonce;
    if (auto sig = id.key.sign(proto::client_auth_string(id.fingerprint, ts, nonce)))
        frame["sig"] = util::b64_encode(*sig);
}

struct Endpoint {
    std::string host;
    std::string port;
    bool tls{false};
};

std::optional<Endpoint> split_url(const std::string& url) {
    std::string rest = url;
    Endpoint ep;
    const std::string lower = util::to_lower(url);
    std::uint16_t default_port = 8787;
    // ws/wss default to the relay's own ports; http/https to the web's, since
    // those are what a URL behind a CDN or reverse proxy will mean.
    if (util::starts_with(lower, "wss://")) {
        ep.tls = true;
        default_port = 8788;
        rest = rest.substr(6);
    } else if (util::starts_with(lower, "https://")) {
        ep.tls = true;
        default_port = 443;
        rest = rest.substr(8);
    } else if (util::starts_with(lower, "ws://")) {
        default_port = 8787;
        rest = rest.substr(5);
    } else if (util::starts_with(lower, "http://")) {
        default_port = 80;
        rest = rest.substr(7);
    }
    if (!rest.empty() && rest.back() == '/') rest.pop_back();
    auto addr = util::parse_address(rest, default_port);
    if (!addr) return std::nullopt;
    ep.host = addr->host;
    ep.port = std::to_string(addr->port);
    return ep;
}

// Runs `ioc` until the pending operation sets `done` or the deadline expires.
bool run_until(net::io_context& ioc, const bool& done, int seconds,
               const std::function<void()>& cancel, const char* what, bool quiet = false) {
    ioc.restart();
    ioc.run_for(std::chrono::seconds(seconds));
    if (done) return true;
    if (cancel) cancel();
    ioc.restart();
    ioc.run_for(std::chrono::milliseconds(250));
    if (!quiet) std::cerr << what << " timed out after " << seconds << "s\n";
    return false;
}

websocket::stream_base::decorator client_decorator() {
    return websocket::stream_base::decorator([](websocket::request_type& req) {
        req.set(http::field::user_agent, "r2r-probe/" R2R_VERSION);
        req.set(http::field::sec_websocket_protocol, proto::kSubprotocol);
    });
}

// One WebSocket connection, plain or TLS.
class Client {
public:
    explicit Client(const Options& opt)
        : opt_(opt), ssl_ctx_(ssl::context::tls_client), deadline_s_(opt.timeout_s) {
        ssl_ctx_.set_verify_mode(ssl::verify_none);
    }

    void set_deadline(int seconds) { deadline_s_ = seconds; }

    bool connect() {
        auto ep = split_url(opt_.url);
        if (!ep) {
            std::cerr << "bad --url: " << opt_.url << "\n";
            return false;
        }

        tcp::resolver resolver(ioc_);
        tcp::resolver::results_type results;
        {
            bool done = false;
            boost::system::error_code r;
            resolver.async_resolve(ep->host, ep->port,
                                   [&](boost::system::error_code ec,
                                       tcp::resolver::results_type res) {
                                       r = ec;
                                       results = std::move(res);
                                       done = true;
                                   });
            if (!run_until(ioc_, done, deadline_s_, [&] { resolver.cancel(); }, "resolve"))
                return false;
            if (r) {
                std::cerr << "resolve failed: " << r.message() << "\n";
                return false;
            }
        }

        const std::string host_header = util::format_address(ep->host, std::stoi(ep->port));

        if (ep->tls) tls_.emplace(ioc_, ssl_ctx_);
        else plain_.emplace(ioc_);

        {
            bool done = false;
            boost::system::error_code r;
            auto handler = [&](boost::system::error_code ec, const tcp::endpoint&) {
                r = ec;
                done = true;
            };
            if (tls_)
                net::async_connect(beast::get_lowest_layer(*tls_).socket(), results, handler);
            else
                net::async_connect(beast::get_lowest_layer(*plain_).socket(), results, handler);
            if (!run_until(ioc_, done, deadline_s_, [this] { cancel(); }, "connect")) return false;
            if (r) {
                std::cerr << "connect failed: " << r.message() << "\n";
                return false;
            }
        }

        if (tls_) {
            if (!SSL_set_tlsext_host_name(tls_->next_layer().native_handle(), ep->host.c_str())) {
                std::cerr << "could not set the TLS server name\n";
                return false;
            }
            bool done = false;
            boost::system::error_code r;
            tls_->next_layer().async_handshake(ssl::stream_base::client,
                                               [&](boost::system::error_code ec) {
                                                   r = ec;
                                                   done = true;
                                               });
            if (!run_until(ioc_, done, deadline_s_, [this] { cancel(); }, "tls handshake"))
                return false;
            if (r) {
                std::cerr << "tls handshake failed: " << r.message() << "\n";
                return false;
            }
        }

        {
            bool done = false;
            boost::system::error_code r;
            auto handler = [&](boost::system::error_code ec) {
                r = ec;
                done = true;
            };
            if (tls_) {
                tls_->set_option(client_decorator());
                tls_->async_handshake(host_header, opt_.path, handler);
            } else {
                plain_->set_option(client_decorator());
                plain_->async_handshake(host_header, opt_.path, handler);
            }
            if (!run_until(ioc_, done, deadline_s_, [this] { cancel(); }, "websocket handshake"))
                return false;
            if (r) {
                std::cerr << "websocket handshake failed: " << r.message() << "\n";
                return false;
            }
        }
        return true;
    }

    bool send(const json& j) {
        const std::string text = j.dump();
        bool done = false;
        boost::system::error_code r;
        auto handler = [&](boost::system::error_code ec, std::size_t) {
            r = ec;
            done = true;
        };
        if (tls_) tls_->async_write(net::buffer(text), handler);
        else plain_->async_write(net::buffer(text), handler);
        if (!run_until(ioc_, done, deadline_s_, [this] { cancel(); }, "write")) return false;
        if (r) {
            std::cerr << "write failed: " << r.message() << "\n";
            return false;
        }
        return true;
    }

    std::optional<json> recv(bool quiet = false) {
        buffer_.clear();
        bool done = false;
        boost::system::error_code r;
        auto handler = [&](boost::system::error_code ec, std::size_t) {
            r = ec;
            done = true;
        };
        if (tls_) tls_->async_read(buffer_, handler);
        else plain_->async_read(buffer_, handler);
        if (!run_until(ioc_, done, deadline_s_, [this] { cancel(); }, "read", quiet))
            return std::nullopt;
        if (r) {
            if (r != websocket::error::closed)
                std::cerr << "read failed: " << r.message() << "\n";
            return std::nullopt;
        }
        auto j = json::parse(beast::buffers_to_string(buffer_.data()), nullptr, false);
        if (j.is_discarded()) return std::nullopt;
        return j;
    }

    // Reads until one of `types` (or an error frame) arrives.
    std::optional<json> await(const std::vector<std::string>& types, int max_frames = 32,
                              bool quiet = false) {
        for (int i = 0; i < max_frames; ++i) {
            auto j = recv(quiet);
            if (!j) return std::nullopt;
            const std::string t = j->value("t", "");
            for (const auto& want : types)
                if (t == want) return j;
            if (t == proto::kError) return j;
        }
        return std::nullopt;
    }

    void close() {
        if (!tls_ && !plain_) return;
        bool done = false;
        auto handler = [&](boost::system::error_code) { done = true; };
        if (tls_) tls_->async_close(websocket::close_code::normal, handler);
        else plain_->async_close(websocket::close_code::normal, handler);
        ioc_.restart();
        ioc_.run_for(std::chrono::seconds(3));
        if (!done) cancel();
    }

private:
    void cancel() {
        if (tls_) beast::get_lowest_layer(*tls_).cancel();
        else if (plain_) beast::get_lowest_layer(*plain_).cancel();
    }

    const Options& opt_;
    net::io_context ioc_;
    ssl::context ssl_ctx_;
    int deadline_s_;
    beast::flat_buffer buffer_;
    std::optional<websocket::stream<beast::tcp_stream>> plain_;
    std::optional<websocket::stream<beast::ssl_stream<beast::tcp_stream>>> tls_;
};

// The header form of the same signed proof the `hello` frame carries.
std::string auth_header(const Identity& id) {
    json proof;
    sign_frame(proof, id);
    return util::b64_encode(proof.dump());
}

struct HttpResult {
    int status{0};
    std::string body;
};

std::optional<HttpResult> http_do(const Options& opt, http::verb method, const std::string& target,
                                  const std::string& body, const std::string& auth,
                                  const char* content_type) {
    const std::string base = opt.http_url.empty() ? opt.url : opt.http_url;
    auto ep = split_url(base);
    if (!ep) return std::nullopt;

    net::io_context ioc;
    ssl::context ssl_ctx(ssl::context::tls_client);
    ssl_ctx.set_verify_mode(ssl::verify_none);

    tcp::resolver resolver(ioc);
    tcp::resolver::results_type results;
    {
        bool done = false;
        boost::system::error_code r;
        resolver.async_resolve(
            ep->host, ep->port,
            [&](boost::system::error_code ec, tcp::resolver::results_type res) {
                r = ec;
                results = std::move(res);
                done = true;
            });
        if (!run_until(ioc, done, opt.timeout_s, [&] { resolver.cancel(); }, "resolve") || r)
            return std::nullopt;
    }

    http::request<http::string_body> req{method, target, 11};
    req.set(http::field::host, util::format_address(ep->host, std::stoi(ep->port)));
    req.set(http::field::user_agent, "r2r-probe/" R2R_VERSION);
    if (!auth.empty()) req.set("X-R2R-Auth", auth);
    if (content_type) req.set(http::field::content_type, content_type);
    if (!body.empty()) {
        req.body() = body;
        req.prepare_payload();
    }
    http::response<http::string_body> res;
    beast::flat_buffer buffer;

    auto exchange = [&](auto& stream) -> bool {
        auto cancel = [&] { beast::get_lowest_layer(stream).cancel(); };
        {
            bool done = false;
            boost::system::error_code r;
            net::async_connect(beast::get_lowest_layer(stream).socket(), results,
                               [&](boost::system::error_code ec, const tcp::endpoint&) {
                                   r = ec;
                                   done = true;
                               });
            if (!run_until(ioc, done, opt.timeout_s, cancel, "connect") || r) return false;
        }
        if constexpr (std::is_same_v<std::decay_t<decltype(stream)>,
                                     beast::ssl_stream<beast::tcp_stream>>) {
            SSL_set_tlsext_host_name(stream.native_handle(), ep->host.c_str());
            bool done = false;
            boost::system::error_code r;
            stream.async_handshake(ssl::stream_base::client,
                                   [&](boost::system::error_code ec) {
                                       r = ec;
                                       done = true;
                                   });
            if (!run_until(ioc, done, opt.timeout_s, cancel, "tls handshake") || r) return false;
        }
        {
            bool done = false;
            boost::system::error_code r;
            http::async_write(stream, req, [&](boost::system::error_code ec, std::size_t) {
                r = ec;
                done = true;
            });
            // A write error is not necessarily fatal: the relay rejects an
            // oversized upload as soon as it reads the headers, so the response
            // is already on its way while we are still sending the body. Fall
            // through and read it.
            if (!run_until(ioc, done, opt.timeout_s, cancel, "http write")) return false;
            if (r) std::cerr << "(upload cut short: " << r.message() << ")\n";
        }
        {
            bool done = false;
            boost::system::error_code r;
            http::async_read(stream, buffer, res, [&](boost::system::error_code ec, std::size_t) {
                r = ec;
                done = true;
            });
            if (!run_until(ioc, done, opt.timeout_s, cancel, "http read") || r) return false;
        }
        return true;
    };

    if (ep->tls) {
        beast::ssl_stream<beast::tcp_stream> stream(ioc, ssl_ctx);
        if (!exchange(stream)) return std::nullopt;
    } else {
        beast::tcp_stream stream(ioc);
        if (!exchange(stream)) return std::nullopt;
    }
    return HttpResult{static_cast<int>(res.result_int()), res.body()};
}

std::optional<std::string> http_get(const Options& opt, const std::string& target) {
    auto r = http_do(opt, http::verb::get, target, "", "", nullptr);
    if (!r) return std::nullopt;
    return r->body;
}

bool say_hello(Client& c, const Options& opt, const Identity* id = nullptr) {
    json hello{{"t", proto::kHello}, {"role", "client"}, {"proto", proto::kVersion}};
    if (id) sign_frame(hello, *id);
    if (!c.send(hello)) return false;
    auto welcome = c.await({proto::kWelcome});
    if (!welcome) {
        std::cerr << "no welcome frame\n";
        return false;
    }
    std::cout << "connected to node " << welcome->value("node_id", "?") << " (proto "
              << welcome->value("proto", 0) << ", " << welcome->value("peers", 0)
              << " verified peers)\n";
    if (welcome->contains("pending"))
        std::cout << "payloads waiting for this identity: " << (*welcome)["pending"] << "\n";
    if (welcome->contains("quota_bytes"))
        std::cout << "storage: " << welcome->value("used_bytes", 0) << " of "
                  << welcome->value("quota_bytes", 0) << " bytes used\n";
    return true;
}

// Joins as a relay with a throwaway key, advertising `advertise`, then offers
// the relay a peer list. This is the shape of a peer-table poisoning attempt;
// the relay must welcome the session (joining needs no permission) yet ignore
// the list until it has dialled `advertise` and found this node there.
int cmd_rogue(const Options& opt, const std::string& advertise, const std::string& list,
              const std::string& point_at = std::string{}) {
    auto key = crypto::NodeIdentity::generate();
    if (!key) {
        std::cerr << "could not generate a node key\n";
        return 1;
    }
    Client c(opt);
    if (!c.connect()) return 1;

    const std::int64_t ts = util::now_unix();
    const std::string nonce = util::hex_encode(crypto::random_bytes(12));
    json hello{{"t", proto::kHello},     {"role", "relay"},
               {"proto", proto::kVersion}, {"node_id", key->node_id()},
               {"advertise", advertise},   {"ed25519", key->ed_pub_b64()},
               {"x25519", key->x_pub_b64()}, {"tls", false},
               {"ts", ts},                 {"nonce", nonce}};
    if (auto sig = key->sign(proto::hello_signing_string(key->node_id(), advertise, ts, nonce)))
        hello["sig"] = util::b64_encode(*sig);
    if (!c.send(hello)) return 1;
    auto reply = c.await({proto::kWelcome, proto::kError});
    if (!reply) {
        std::cerr << "no reply to the relay hello\n";
        return 1;
    }
    if (reply->value("t", "") != proto::kWelcome) {
        std::cout << "relay hello refused: " << reply->dump() << "\n";
        return 1;
    }
    std::cout << "welcomed as relay " << key->node_id().substr(0, 8) << " advertising " << advertise
              << " (" << reply->value("peers", 0) << " verified peers there)\n";

    json peers = json::array();
    for (const auto& a : util::split(list, ','))
        if (!util::trim(a).empty()) peers.push_back({{"address", util::trim(a)}, {"tls", false}});
    if (!c.send(json{{"t", proto::kPeers}, {"peers", peers}})) return 1;
    std::cout << "offered " << peers.size() << " peer address(es)\n";
    if (!point_at.empty()) {
        // A forged mail pointer: "fingerprint X has 7 payloads waiting at my
        // address", signed with the throwaway key. Only a relay this node has
        // verified may say that, so the relay must drop it.
        const std::int64_t pts = util::now_unix();
        json ptr{{"t", proto::kPointer}, {"fp", point_at},     {"address", advertise},
                 {"count", 7},           {"ts", pts},          {"node_id", key->node_id()},
                 {"ed25519", key->ed_pub_b64()}, {"hops", 2}};
        if (auto psig = key->sign(proto::pointer_signing_string(point_at, advertise, pts)))
            ptr["sig"] = util::b64_encode(*psig);
        if (!c.send(ptr)) return 1;
        std::cout << "pointer sent for " << point_at.substr(0, 12) << "… at " << advertise << "\n";
        // And a collection request. The authorisation inside cannot be forged
        // (it is the identity's own signature), so this one carries junk; the
        // relay must refuse the link before it even looks at the signature.
        json col{{"t", proto::kCollect},   {"fp", point_at},        {"pubkey", key->ed_pub_b64()},
                 {"scope", "collect"},     {"holder", "0.0.0.0:1"},  {"ts", pts},
                 {"nonce", util::hex_encode(crypto::random_bytes(12))}, {"sig", "AA=="},
                 {"want_max", 200}};
        if (!c.send(col)) return 1;
        std::cout << "collect sent for " << point_at.substr(0, 12) << "…\n";
    }
    // Give the relay a moment to react (an error frame would arrive here);
    // then hang up. What it did with the list shows in its log and status.
    c.set_deadline(2);
    if (auto err = c.await({proto::kError}, 32, true))
        std::cout << "relay answered: " << err->dump() << "\n";
    c.close();
    return 0;
}

// Mints a storage voucher the way a wallet does (§14.4): prints the payment
// key's address and the EIP-191 signature, for feeding to a `voucher` frame.
int cmd_voucher_sign(const std::string& priv_hex, const std::string& vault, long chain_id,
                     const std::string& payout, long cumulative) {
    auto priv = util::hex_decode(priv_hex.rfind("0x", 0) == 0 ? priv_hex.substr(2) : priv_hex);
    if (!priv || priv->size() != 32) {
        std::cerr << "the payment key must be 32 bytes of hex\n";
        return 2;
    }
    const crypto::Bytes digest = crypto::evm_voucher_digest(vault, chain_id, payout, cumulative);
    auto address = crypto::evm_address_of(*priv);
    if (digest.empty() || !address) {
        std::cerr << "vault and payout must be 0x addresses, chain id and cumulative positive\n";
        return 2;
    }
    auto sig = crypto::evm_sign(*priv, digest);
    if (!sig) {
        std::cerr << "signing failed\n";
        return 1;
    }
    std::cout << "address " << *address << "\n"
              << "digest 0x" << util::hex_encode(digest) << "\n"
              << "sig 0x" << util::hex_encode(*sig) << "\n";
    return 0;
}

// The relay-side check, standalone: which address signed this voucher?
int cmd_voucher_check(const std::string& vault, long chain_id, const std::string& payout,
                      long cumulative, const std::string& sig_hex) {
    const crypto::Bytes digest = crypto::evm_voucher_digest(vault, chain_id, payout, cumulative);
    auto sig = util::hex_decode(sig_hex.rfind("0x", 0) == 0 ? sig_hex.substr(2) : sig_hex);
    if (digest.empty() || !sig) {
        std::cerr << "bad inputs\n";
        return 2;
    }
    auto who = crypto::evm_recover_address(digest, *sig);
    if (!who) {
        std::cout << "signature does not recover to any address\n";
        return 1;
    }
    std::cout << "signer " << *who << "\n";
    return 0;
}

// Prints the X-R2R-Auth header value for this identity: one fresh, signed
// proof. Presenting it twice must fail the second time.
int cmd_authheader(const Options& opt) {
    auto id = load_identity(opt.key_path);
    if (!id) {
        std::cerr << "could not load or create the identity key at " << opt.key_path << "\n";
        return 1;
    }
    std::cout << auth_header(*id) << "\n";
    return 0;
}

int cmd_status(const Options& opt) {
    auto status = http_get(opt, "/status.json");
    if (!status) {
        std::cerr << "could not reach the relay over HTTP\n";
        return 1;
    }
    auto j = json::parse(*status, nullptr, false);
    std::cout << (j.is_discarded() ? *status : j.dump(2)) << "\n";
    return 0;
}

int cmd_peers(const Options& opt) {
    auto body = http_get(opt, "/peers.json");
    if (!body) {
        std::cerr << "could not reach the relay over HTTP\n";
        return 1;
    }
    std::cout << *body << "\n";
    return 0;
}

int cmd_ping(const Options& opt) {
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt)) return 1;
    const std::string nonce = util::hex_encode(crypto::random_bytes(8));
    const auto t0 = std::chrono::steady_clock::now();
    if (!c.send(json{{"t", proto::kPing}, {"nonce", nonce}})) return 1;
    auto pong = c.await({proto::kPong});
    if (!pong || pong->value("t", "") != proto::kPong) {
        std::cerr << "no pong\n";
        return 1;
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
    const bool matched = pong->value("nonce", "") == nonce;
    std::cout << "pong in " << ms << " ms (nonce " << (matched ? "matches" : "MISMATCH") << ")\n";
    c.close();
    return matched ? 0 : 1;
}

// Sends one arbitrary JSON frame after an identified hello and prints the
// first reply. The workhorse for exercising admin frames from a shell.
int cmd_frame(const Options& opt, const std::string& raw, const std::string& reply_type) {
    json frame = json::parse(raw, nullptr, false);
    if (frame.is_discarded() || !frame.is_object() || !frame.contains("t")) {
        std::cerr << "frame needs a JSON object with a \"t\" field\n";
        return 2;
    }
    auto id = load_identity(opt.key_path);
    if (!id) {
        std::cerr << "could not load or create the identity key at " << opt.key_path << "\n";
        return 1;
    }
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt, opt.anonymous ? nullptr : &*id)) return 1;
    if (!c.send(frame)) return 1;
    const std::string type = frame.value("t", std::string{});
    auto reply = c.await({reply_type.empty() ? type : reply_type, proto::kAdminOk});
    if (!reply) return 1;
    std::cout << reply->dump(2) << "\n";
    c.close();
    return reply->value("t", "") == proto::kError ? 1 : 0;
}

// Signs a single-use, holder-bound collection authorization for each named
// relay and asks the connected relay to gather the mail home.
int cmd_deposit(const Options& opt, const std::string& holders, const std::string& scope) {
    auto id = load_identity(opt.key_path);
    if (!id) {
        std::cerr << "could not load or create the identity key at " << opt.key_path << "\n";
        return 1;
    }
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt, &*id)) return 1;

    json targets = json::array();
    std::string part;
    for (std::size_t i = 0; i <= holders.size(); ++i) {
        if (i == holders.size() || holders[i] == ',') {
            if (!part.empty()) {
                const std::int64_t ts = util::now_unix();
                const std::string nonce = util::hex_encode(crypto::random_bytes(12));
                auto sig = id->key.sign(
                    proto::collect_signing_string(id->fingerprint, part, scope, ts, nonce));
                if (!sig) return 1;
                targets.push_back({{"address", part},
                                   {"ts", ts},
                                   {"nonce", nonce},
                                   {"sig", util::b64_encode(*sig)}});
            }
            part.clear();
        } else {
            part += holders[i];
        }
    }
    json frame{{"t", proto::kDeposit},
               {"id", id->fingerprint},
               {"pubkey", id->key.ed_pub_b64()},
               {"scope", scope},
               {"targets", targets}};
    if (!c.send(frame)) return 1;
    auto reply = c.await({proto::kDepositOk});
    if (!reply) return 1;
    std::cout << reply->dump(2) << "\n";
    c.close();
    return reply->value("t", "") == proto::kError ? 1 : 0;
}

int cmd_claim(const Options& opt, const std::string& code) {
    auto id = load_identity(opt.key_path);
    if (!id) {
        std::cerr << "could not load or create the identity key at " << opt.key_path << "\n";
        return 1;
    }

    Client c(opt);
    if (!c.connect() || !say_hello(c, opt, &*id)) return 1;

    std::cout << "claiming as identity " << id->fingerprint << "\n";
    json claim{{"t", proto::kInviteClaim}, {"code", code}};
    sign_frame(claim, *id);
    if (!c.send(claim)) return 1;

    auto reply = c.await({proto::kInviteOk});
    if (!reply) return 1;
    if (reply->value("t", "") == proto::kError) {
        std::cerr << "claim refused: " << reply->value("code", "?") << " ("
                  << reply->value("msg", "") << ")\n";
        return 1;
    }
    std::cout << "invite burned. Home relay: " << reply->value("home_relay", "") << "\n";
    std::cout << "three fresh single-use codes:\n";
    for (const auto& v : reply->value("invites", json::array()))
        std::cout << "  " << v.get<std::string>() << "\n";
    c.close();
    return 0;
}

int cmd_send(const Options& opt, const std::string& to, const std::string& text) {
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt)) return 1;
    const std::string id = crypto::uuid_v4();
    if (!c.send(json{{"t", proto::kSend}, {"id", id}, {"to", to},
                     {"body", util::b64_encode(text)}}))
        return 1;
    auto reply = c.await({proto::kSent});
    if (!reply) return 1;
    if (reply->value("t", "") == proto::kError) {
        std::cerr << "refused: " << reply->value("code", "?") << " (" << reply->value("msg", "")
                  << ")\n";
        return 1;
    }
    std::cout << "payload " << id << ": " << reply->value("status", "?");
    if (reply->contains("via")) std::cout << " via " << (*reply)["via"].get<std::string>();
    if (reply->contains("expires_at")) {
        const auto expires = reply->value("expires_at", std::int64_t{0});
        std::cout << ", expires " << util::iso8601(expires) << " (in "
                  << util::human_duration(expires - util::now_unix()) << ")";
    }
    std::cout << "\n";
    c.close();
    return 0;
}

int cmd_fetch(const Options& opt) {
    auto id = load_identity(opt.key_path);
    if (!id) {
        std::cerr << "could not load or create the identity key at " << opt.key_path << "\n";
        return 1;
    }
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt, &*id)) return 1;
    if (!c.send(json{{"t", proto::kFetch}, {"since", 0}, {"max", 64}})) return 1;

    std::vector<std::string> ids;
    for (int i = 0; i < 200; ++i) {
        auto j = c.recv();
        if (!j) break;
        const std::string t = j->value("t", "");
        if (t == proto::kDrop) {
            ids.push_back(j->value("id", ""));
            auto body = util::b64_decode(j->value("body", ""));
            std::cout << "drop " << j->value("id", "") << " (" << (body ? body->size() : 0)
                      << " bytes, stored "
                      << util::iso8601(j->value("created_at", std::int64_t{0})) << ")\n";
            if (body) {
                std::string preview(body->begin(), body->end());
                if (preview.size() > 200) preview.resize(200);
                bool printable = true;
                for (unsigned char ch : preview)
                    if (ch < 0x09 || (ch > 0x0d && ch < 0x20)) printable = false;
                std::cout << "  " << (printable ? preview : "<binary payload>") << "\n";
            }
        } else if (t == proto::kFetchDone) {
            std::cout << "fetched " << j->value("count", 0) << " payloads\n";
            break;
        } else if (t == proto::kError) {
            std::cerr << "error: " << j->value("code", "?") << " (" << j->value("msg", "") << ")\n";
            return 1;
        }
    }

    if (!ids.empty()) {
        c.send(json{{"t", proto::kAck}, {"ids", ids}});
        if (auto ack = c.await({"ack_ok"}))
            std::cout << "acknowledged " << ack->value("removed", 0) << " payloads\n";
    }
    c.close();
    return 0;
}

int cmd_onion(const Options& opt, const std::string& to, const std::string& text) {
    if (opt.hops.empty()) {
        std::cerr << "onion needs --hops host:port[,host:port...]\n";
        return 1;
    }
    auto peers_body = http_get(opt, "/peers.json");
    if (!peers_body) {
        std::cerr << "could not read /peers.json to learn the hop keys\n";
        return 1;
    }
    auto doc = json::parse(*peers_body, nullptr, false);
    if (doc.is_discarded()) return 1;

    // Sealing keys for every relay we know about, including this one.
    std::map<std::string, std::string> keys;
    if (doc.contains("node") && doc["node"].is_object()) {
        const std::string addr = doc["node"].value("advertise", "");
        if (!addr.empty()) keys[addr] = doc["node"].value("x25519", "");
    }
    for (const auto& p : doc.value("peers", json::array())) {
        const std::string addr = p.value("address", "");
        if (!addr.empty()) keys[addr] = p.value("x25519", "");
    }

    // --hops a,b|c,d : positions separated by commas, alternatives by '|'.
    std::vector<std::vector<onion::Hop>> route;
    for (const auto& pos : opt.hops) {
        std::vector<onion::Hop> set;
        for (const auto& raw : util::split(pos, '|')) {
            bool tls = false;
            auto canon = PeerRegistry::canonicalise(raw, tls);
            if (!canon) {
                std::cerr << "bad hop: " << raw << "\n";
                return 1;
            }
            auto it = keys.find(*canon);
            if (it == keys.end() || it->second.empty()) {
                std::cerr << "no x25519 key known for hop " << *canon
                          << " (it must appear in /peers.json)\n";
                return 1;
            }
            set.push_back({*canon, it->second});
        }
        if (set.empty() || set.size() > crypto::kMaxSlots) {
            std::cerr << "each position needs 1.." << crypto::kMaxSlots << " relays\n";
            return 1;
        }
        route.push_back(std::move(set));
    }

    onion::Terminal terminal;
    terminal.to = to;
    // The first terminal candidate is the recipient's relay; alternatives
    // forward there, or park the payload with a pointer if it is down.
    terminal.home = route.back().front().address;
    terminal.msg_id = crypto::uuid_v4();
    terminal.body.assign(text.begin(), text.end());

    auto blob = onion::build(route, terminal);
    if (!blob) {
        std::cerr << "could not seal the route\n";
        return 1;
    }
    std::cout << "sealed " << route.size() << " layer(s) into " << blob->size() << " bytes\n";

    Client c(opt);
    if (!c.connect() || !say_hello(c, opt)) return 1;
    if (!c.send(json{{"t", proto::kOnion}, {"blob", util::b64_encode(*blob)}})) return 1;

    // A relay stays silent when a layer is accepted -- telling the previous hop
    // that the route ended here would leak exactly what onion routing hides.
    // Only a failure comes back, so wait briefly and treat silence as success.
    c.set_deadline(2);
    auto reply = c.await({proto::kError}, 2, /*quiet=*/true);
    if (reply && reply->value("t", "") == proto::kError) {
        std::cerr << "relay refused the onion: " << reply->value("code", "?") << " ("
                  << reply->value("msg", "") << ")\n";
        return 1;
    }
    std::cout << "onion accepted; terminal payload id " << terminal.msg_id << "\n";
    c.close();
    return 0;
}

int cmd_ice(const Options& opt) {
    auto id = load_identity(opt.key_path);
    if (!id) return 1;
    auto r = http_do(opt, http::verb::get, "/ice", "", auth_header(*id), nullptr);
    if (!r) { std::cerr << "could not reach the relay\n"; return 1; }
    if (r->status != 200) { std::cerr << "HTTP " << r->status << ": " << r->body << "\n"; return 1; }
    std::cout << r->body << "\n";
    return 0;
}

// Uploads a file as a voice/video message, downloads it back, and checks the
// bytes match the id the relay returned.
int cmd_blob(const Options& opt, const std::string& path) {
    auto id = load_identity(opt.key_path);
    if (!id) return 1;
    auto contents = util::read_file(path);
    if (!contents) { std::cerr << "cannot read " << path << "\n"; return 1; }

    auto up = http_do(opt, http::verb::post, "/blob", *contents, auth_header(*id),
                      "application/octet-stream");
    if (!up) { std::cerr << "upload failed to reach the relay\n"; return 1; }
    if (up->status != 200) { std::cerr << "upload HTTP " << up->status << ": " << up->body << "\n"; return 1; }
    auto j = json::parse(up->body, nullptr, false);
    if (j.is_discarded()) return 1;
    const std::string blob_id = j.value("id", "");
    std::cout << "uploaded " << contents->size() << " bytes as " << blob_id
              << (j.value("duplicate", false) ? " (already stored)" : "") << "\n";

    auto down = http_do(opt, http::verb::get, "/blob/" + blob_id, "", auth_header(*id), nullptr);
    if (!down || down->status != 200) { std::cerr << "download failed\n"; return 1; }
    const std::string got_hash = util::hex_encode(crypto::sha256(down->body));
    const bool intact = (down->body == *contents) && (got_hash == blob_id);
    std::cout << "downloaded " << down->body.size() << " bytes, content hash "
              << (intact ? "matches" : "MISMATCH") << "\n";
    return intact ? 0 : 1;
}

// Appends an entry to this identity's history, then reads the log back the way
// a fresh browser would.
int cmd_journal(const Options& opt, const std::string& text) {
    auto id = load_identity(opt.key_path);
    if (!id) return 1;
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt, &*id)) return 1;

    if (!text.empty()) {
        if (!c.send(json{{"t", proto::kJournalAppend}, {"data", util::b64_encode(text)}})) return 1;
        auto ok = c.await({proto::kJournalOk});
        if (!ok) return 1;
        if (ok->value("t", "") == proto::kError) {
            std::cerr << "append refused: " << ok->value("code", "?") << "\n";
            return 1;
        }
        std::cout << "appended entry seq " << ok->value("seq", 0) << "\n";
    }

    if (!c.send(json{{"t", proto::kJournalRead}, {"since", 0}, {"max", 50}})) return 1;
    auto log = c.await({proto::kJournal});
    if (!log) return 1;
    const auto entries = log->value("entries", json::array());
    std::cout << "history holds " << entries.size() << " entries:\n";
    for (const auto& e : entries) {
        auto d = util::b64_decode(e.value("data", ""));
        std::string s = d ? std::string(d->begin(), d->end()) : "<undecodable>";
        if (s.size() > 120) s.resize(120);
        std::cout << "  seq " << e.value("seq", 0) << ": " << s << "\n";
    }
    c.close();
    return 0;
}

// Stays connected and prints whatever arrives: the other half of a call test.
int cmd_listen(const Options& opt, int seconds) {
    auto id = load_identity(opt.key_path);
    if (!id) return 1;
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt, &*id)) return 1;
    // Live push: drops arrive as they are stored, no fetch needed.
    if (!c.send(json{{"t", proto::kSubscribe}, {"push", true}})) return 1;
    std::cout << "listening as " << id->fingerprint << " for " << seconds << "s\n";
    std::cout.flush();
    c.set_deadline(seconds);
    for (;;) {
        auto f = c.recv(true);
        if (!f) break;
        const std::string t = f->value("t", "");
        if (t == proto::kSig) {
            auto body = util::b64_decode(f->value("body", ""));
            std::cout << "SIG from " << f->value("from", "?") << ": "
                      << (body ? std::string(body->begin(), body->end()) : "<binary>") << "\n";
        } else if (t == proto::kPresence) {
            std::cout << "PRESENCE " << f->value("id", "?") << " is " << f->value("state", "?")
                      << "\n";
        } else if (t == proto::kMail) {
            std::cout << "MAIL pending=" << f->value("pending", 0) << "\n";
        } else if (t == proto::kDrop) {
            auto body = util::b64_decode(f->value("body", ""));
            std::cout << "DROP " << f->value("id", "?") << ": "
                      << (body ? std::string(body->begin(), body->end()) : "<binary>") << "\n";
        } else if (t == proto::kMailAt) {
            std::cout << "MAIL_AT " << f->value("address", "?") << " count="
                      << f->value("count", 0) << "\n";
        } else {
            std::cout << f->dump() << "\n";
        }
        std::cout.flush();
    }
    c.close();
    return 0;
}

int cmd_sig(const Options& opt, const std::string& to, const std::string& text) {
    auto id = load_identity(opt.key_path);
    if (!id) return 1;
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt, &*id)) return 1;
    if (!c.send(json{{"t", proto::kSig}, {"to", to}, {"body", util::b64_encode(text)},
                     {"call", "offer"}}))
        return 1;
    c.set_deadline(3);
    auto reply = c.await({proto::kError}, 2, /*quiet=*/true);
    if (reply && reply->value("t", "") == proto::kError) {
        std::cerr << "signalling refused: " << reply->value("code", "?") << " ("
                  << reply->value("msg", "") << ")\n";
        return 1;
    }
    std::cout << "signalling frame delivered to " << to << "\n";
    c.close();
    return 0;
}

int cmd_watch(const Options& opt, const std::string& target) {
    auto id = load_identity(opt.key_path);
    if (!id) return 1;
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt, &*id)) return 1;
    if (!c.send(json{{"t", proto::kWatch}, {"ids", json::array({target})}})) return 1;
    auto p = c.await({proto::kPresence});
    if (!p) return 1;
    std::cout << p->value("id", "?") << " is " << p->value("state", "?") << " (last seen "
              << p->value("seen", 0) << ")\n";
    c.close();
    return 0;
}

// The three relay-owner actions, which is what the wallet's owner panel does.
// They are ordinary frames on an ordinary connection: the only thing that
// makes them work is that the relay has this fingerprint in its owners table.
int cmd_accounts(const Options& opt) {
    auto id = load_identity(opt.key_path);
    if (!id) return 1;
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt, &*id)) return 1;
    if (!c.send(json{{"t", proto::kAdminAccounts}, {"max", 100}})) return 1;
    auto r = c.await({proto::kAdminAccounts});
    if (!r) return 1;
    if (r->value("t", "") == proto::kError) {
        std::cerr << "refused: " << r->value("code", "?") << " (" << r->value("msg", "") << ")\n";
        return 1;
    }
    const auto accounts = r->value("accounts", json::array());
    std::cout << accounts.size() << " identities on this relay (default allowance "
              << r->value("default_quota_bytes", 0) << " bytes):\n";
    for (const auto& a : accounts)
        std::cout << "  " << a.value("id", "").substr(0, 16) << "…  "
                  << a.value("used_bytes", 0) << " / " << a.value("quota_bytes", 0) << " bytes"
                  << (a.value("custom_quota", false) ? " (custom)" : "")
                  << (a.value("online", false) ? "  online" : "") << "\n";
    c.close();
    return 0;
}

int cmd_setquota(const Options& opt, const std::string& target, const std::string& mb) {
    auto id = load_identity(opt.key_path);
    if (!id) return 1;
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt, &*id)) return 1;
    json req{{"t", proto::kAdminSetQuota}, {"id", target}};
    if (mb == "default") req["mb"] = nullptr;
    else req["mb"] = std::atoll(mb.c_str());
    if (!c.send(req)) return 1;
    auto r = c.await({proto::kAdminOk});
    if (!r) return 1;
    if (r->value("t", "") == proto::kError) {
        std::cerr << "refused: " << r->value("code", "?") << " (" << r->value("msg", "") << ")\n";
        return 1;
    }
    std::cout << r->value("id", "").substr(0, 16) << "… allowance is now "
              << r->value("quota_bytes", 0) << " bytes (using " << r->value("used_bytes", 0)
              << ")\n";
    c.close();
    return 0;
}

int cmd_mkinvites(const Options& opt, int count) {
    auto id = load_identity(opt.key_path);
    if (!id) return 1;
    Client c(opt);
    if (!c.connect() || !say_hello(c, opt, &*id)) return 1;
    if (!c.send(json{{"t", proto::kAdminInvites}, {"count", count}})) return 1;
    auto r = c.await({proto::kAdminInvites});
    if (!r) return 1;
    if (r->value("t", "") == proto::kError) {
        std::cerr << "refused: " << r->value("code", "?") << " (" << r->value("msg", "") << ")\n";
        return 1;
    }
    for (const auto& v : r->value("invites", json::array()))
        std::cout << "  " << v.get<std::string>() << "\n";
    c.close();
    return 0;
}

int cmd_whoami(const Options& opt) {
    auto id = load_identity(opt.key_path);
    if (!id) {
        std::cerr << "could not load or create the identity key at " << opt.key_path << "\n";
        return 1;
    }
    std::cout << id->fingerprint << "\n";
    return 0;
}

void usage() {
    std::cout <<
        "r2r-probe " R2R_VERSION "\n\n"
        "Usage: r2r-probe [options] <command> [args]\n\n"
        "Commands:\n"
        "  status                      counters from /status.json\n"
        "  peers                       the relay's published peer list\n"
        "  ping                        WebSocket round trip\n"
        "  whoami                      print the fingerprint of the identity key\n"
        "  claim <uuid>                burn an invite code\n"
        "  send <fingerprint> <text>   leave a payload in the dead drop\n"
        "  fetch                       collect this identity's payloads and ack them\n"
        "  onion <fingerprint> <text>  send through a sealed multi-hop route\n"
        "  journal [text]              append to this identity's history, then read it back\n"
        "  blob <file>                 upload a voice/video message and verify the round trip\n"
        "  ice                         STUN/TURN servers for establishing a call\n"
        "  listen [seconds]            stay connected and print signalling and presence\n"
        "  sig <fingerprint> <text>    send a call signalling frame to a connected peer\n"
        "  watch <fingerprint>         report whether that identity is online\n"
        "\n"
        "Storage market (what the wallet signs):\n"
        "  voucher-sign <priv> <vault> <chain> <payout> <cumulative>\n"
        "                              mint a voucher signature with a secp256k1 key\n"
        "  voucher-check <vault> <chain> <payout> <cumulative> <sig>\n"
        "                              recover the signer, as the relay does\n"
        "\n"
        "Peer-table hygiene:\n"
        "  rogue <advertise> <addrs> [fp]\n"
        "                              join as a self-signed relay, gossip <addrs> and,\n"
        "                              with fp, plant a forged mail pointer; the relay\n"
        "                              must act on none of it\n"
        "\n"
        "Relay owner (what the wallet's owner panel does):\n"
        "  accounts                    list identities, their usage and allowances\n"
        "  setquota <fp> <MB|default>  change one identity's allowance\n"
        "  mkinvites [n]               mint invite codes\n\n"
        "Options:\n"
        "  --url URL     relay WebSocket URL (default ws://127.0.0.1:8787)\n"
        "  --http URL    HTTP base URL, if it differs from --url\n"
        "  --key PATH    ed25519 identity key, created if absent\n"
        "                (default $HOME/.r2r-probe.key)\n"
        "  --path P      upgrade request path (default /r2r; use /ws behind nginx)\n"
        "  --anonymous   with `frame`: hello without proving an identity\n"
        "  authheader    (command) print one X-R2R-Auth header value for --key\n"
        "  --hops LIST   comma-separated onion hops, in order\n"
        "  --timeout N   per-operation deadline in seconds (default 15)\n";
}

}  // namespace

int main(int argc, char** argv) {
    crypto::init();

    Options opt;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string{}; };
        if (a == "--url") opt.url = next();
        else if (a == "--http") opt.http_url = next();
        else if (a == "--key") opt.key_path = next();
        else if (a == "--anonymous") opt.anonymous = true;
        else if (a == "--path") opt.path = next();
        else if (a == "--timeout") opt.timeout_s = std::max(1, std::atoi(next().c_str()));
        else if (a == "--hops") {
            for (auto& h : util::split(next(), ',')) {
                const std::string t = util::trim(h);
                if (!t.empty()) opt.hops.push_back(t);
            }
        } else if (a == "--help" || a == "-h") {
            usage();
            return 0;
        } else {
            args.push_back(a);
        }
    }

    if (args.empty()) {
        usage();
        return 2;
    }

    if (opt.key_path.empty()) {
        const char* home = std::getenv("HOME");
        opt.key_path = std::string(home ? home : ".") + "/.r2r-probe.key";
    }

    const std::string& cmd = args[0];
    if (cmd == "whoami") return cmd_whoami(opt);
    if (cmd == "ice") return cmd_ice(opt);
    if (cmd == "blob") {
        if (args.size() < 2) { std::cerr << "blob needs a file path\n"; return 2; }
        return cmd_blob(opt, args[1]);
    }
    if (cmd == "journal") return cmd_journal(opt, args.size() > 1 ? args[1] : std::string{});
    if (cmd == "listen") return cmd_listen(opt, args.size() > 1 ? std::atoi(args[1].c_str()) : 10);
    if (cmd == "sig") {
        if (args.size() < 3) { std::cerr << "sig needs <fingerprint> <text>\n"; return 2; }
        return cmd_sig(opt, args[1], args[2]);
    }
    if (cmd == "watch") {
        if (args.size() < 2) { std::cerr << "watch needs a fingerprint\n"; return 2; }
        return cmd_watch(opt, args[1]);
    }
    if (cmd == "accounts") return cmd_accounts(opt);
    if (cmd == "setquota") {
        if (args.size() < 3) { std::cerr << "setquota needs <fingerprint> <MB|default>\n"; return 2; }
        return cmd_setquota(opt, args[1], args[2]);
    }
    if (cmd == "mkinvites") return cmd_mkinvites(opt, args.size() > 1 ? std::atoi(args[1].c_str()) : 3);
    if (cmd == "status") return cmd_status(opt);
    if (cmd == "authheader") return cmd_authheader(opt);
    if (cmd == "peers") return cmd_peers(opt);
    if (cmd == "ping") return cmd_ping(opt);
    if (cmd == "voucher-sign") {
        if (args.size() < 6) { std::cerr << "voucher-sign needs <privkey-hex> <vault> <chain-id> <payout> <cumulative>\n"; return 2; }
        return cmd_voucher_sign(args[1], args[2], std::atol(args[3].c_str()), args[4], std::atol(args[5].c_str()));
    }
    if (cmd == "voucher-check") {
        if (args.size() < 6) { std::cerr << "voucher-check needs <vault> <chain-id> <payout> <cumulative> <sig>\n"; return 2; }
        return cmd_voucher_check(args[1], std::atol(args[2].c_str()), args[3], std::atol(args[4].c_str()), args[5]);
    }
    if (cmd == "rogue") {
        if (args.size() < 3) { std::cerr << "rogue needs <advertise> <addr[,addr...]> [fingerprint]\n"; return 2; }
        return cmd_rogue(opt, args[1], args[2], args.size() > 3 ? args[3] : std::string{});
    }
    if (cmd == "claim") {
        if (args.size() < 2) { std::cerr << "claim needs an invite code\n"; return 2; }
        return cmd_claim(opt, args[1]);
    }
    if (cmd == "send") {
        if (args.size() < 3) { std::cerr << "send needs <fingerprint> <text>\n"; return 2; }
        return cmd_send(opt, args[1], args[2]);
    }
    if (cmd == "fetch") return cmd_fetch(opt);
    if (cmd == "frame") {
        if (args.size() < 2) { std::cerr << "frame needs a JSON object\n"; return 2; }
        return cmd_frame(opt, args[1], args.size() > 2 ? args[2] : std::string{});
    }
    if (cmd == "deposit") {
        if (args.size() < 2) { std::cerr << "deposit needs <holder[,holder…]> [scope]\n"; return 2; }
        return cmd_deposit(opt, args[1], args.size() > 2 ? args[2] : "collect-delete");
    }
    if (cmd == "onion") {
        if (args.size() < 3) { std::cerr << "onion needs <fingerprint> <text>\n"; return 2; }
        return cmd_onion(opt, args[1], args[2]);
    }

    std::cerr << "unknown command: " << cmd << "\n";
    usage();
    return 2;
}
