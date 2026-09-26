// The wss:// half of the inbound path. See session_factory.hpp for why this is
// a translation unit of its own.
#include "http_session.hpp"
#include "session_factory.hpp"

namespace r2r {

void start_tls_session(boost::asio::ip::tcp::socket socket, ServerContext& ctx,
                       boost::asio::ssl::context& tls) {
    std::make_shared<TlsHttpSession>(std::move(socket), ctx, tls)->run();
}

}  // namespace r2r
