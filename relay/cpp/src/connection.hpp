// R2R relay -- transport-neutral view of one WebSocket connection.
//
// The application layer (Hub) only ever sees this interface, which is why the
// same routing, storage and gossip logic serves ws:// and wss:// identically.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace r2r {

enum class ConnKind {
    inbound,        // someone connected to us (client or relay; decided by `hello`)
    outbound_peer,  // we dialled another relay
};

class Connection {
public:
    virtual ~Connection() = default;

    virtual void send_text(std::string msg) = 0;
    virtual void close_now(std::uint16_t code, std::string reason) = 0;

    virtual const std::string& id() const noexcept = 0;   // random, per-connection
    virtual bool secure() const noexcept = 0;             // arrived over TLS
    virtual ConnKind kind() const noexcept = 0;
    // Peer address for links we dialled; empty for inbound connections, whose
    // remote address is deliberately never retained anywhere.
    virtual const std::string& dialled_address() const noexcept = 0;
    virtual std::size_t queue_depth() const noexcept = 0;
};

using ConnectionPtr = std::shared_ptr<Connection>;

class ChannelSink {
public:
    virtual ~ChannelSink() = default;
    virtual void on_open(const ConnectionPtr& c) = 0;
    virtual void on_text(const ConnectionPtr& c, std::string&& msg) = 0;
    virtual void on_close(const ConnectionPtr& c) = 0;
};

}  // namespace r2r
