// The ws:// half of the inbound path. See session_factory.hpp for why this is
// a translation unit of its own.
#include "http_session.hpp"
#include "session_factory.hpp"

namespace r2r {

void start_plain_session(boost::asio::ip::tcp::socket socket, ServerContext& ctx) {
    std::make_shared<PlainHttpSession>(std::move(socket), ctx)->run();
}

}  // namespace r2r
