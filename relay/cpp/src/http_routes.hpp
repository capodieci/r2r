// R2R relay -- plain HTTP served on the same two ports as the WebSocket.
//
//   GET  /                    status landing page
//   GET  /peers.json          verified peer list (this is the bootstrap file)
//   GET  /node.json           node id and public keys
//   GET  /status.json         machine-readable counters
//   GET  /health              liveness probe
//   GET  /invite/check/<uuid> is this code still open? (does not burn it)
//   POST /invite/claim        burn a code, register an identity, get 3 codes
//   POST /blob                upload a voice or video message, returns its id
//   GET  /blob/<id>           fetch one back
//   GET  /ice                 STUN/TURN servers for establishing a direct call
//
// The last three authenticate with an `X-R2R-Auth` header carrying the same
// base64 signed proof used by the `hello` frame.
#pragma once

#include <boost/beast/http.hpp>

#include <cstdint>
#include <string>

#include "blobstore.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "db.hpp"
#include "hub.hpp"
#include "peers.hpp"

namespace r2r {

namespace http = boost::beast::http;

class Doorway;

struct ServerContext {
    Hub& hub;
    PeerRegistry& peers;
    Db& db;
    BlobStore& blobs;
    const Config& cfg;
    const crypto::NodeIdentity& node;
    std::int64_t started_at{0};
    // Set when the build carries the doorway module and a bundle loaded.
    Doorway* doorway{nullptr};
};

http::response<http::string_body> handle_http_request(
    const http::request<http::string_body>& req, ServerContext& ctx, bool secure);

}  // namespace r2r
