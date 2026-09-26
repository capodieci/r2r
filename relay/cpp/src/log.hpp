// R2R relay -- structured stdout logger.
//
// PRIVACY CONTRACT
// ----------------
// Nothing that identifies a *user* may ever reach this logger:
//   * no remote IP addresses or ports of inbound connections,
//   * no message payloads (they are ciphertext anyway) or payload hashes,
//   * no invite codes, no full identity fingerprints.
// Peer relay addresses ARE logged: they are public infrastructure and are
// published in peers.json. Inbound sessions are identified only by a random
// per-connection id that is discarded when the socket closes.
#pragma once

#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace r2r::log {

enum class Level : int { trace = 0, debug, info, warn, error, off };

void set_level(Level lvl);
Level get_level();
bool enabled(Level lvl);
std::optional<Level> level_from_string(std::string_view s);
const char* level_name(Level lvl);

// Emits one line: "2026-08-04T14:00:00Z INFO  message"
void write_line(Level lvl, const std::string& msg);

namespace detail {
template <class... Args>
std::string cat(Args&&... args) {
    std::ostringstream os;
    (os << ... << std::forward<Args>(args));
    return os.str();
}
}  // namespace detail

template <class... Args> void trace(Args&&... a) {
    if (enabled(Level::trace)) write_line(Level::trace, detail::cat(std::forward<Args>(a)...));
}
template <class... Args> void debug(Args&&... a) {
    if (enabled(Level::debug)) write_line(Level::debug, detail::cat(std::forward<Args>(a)...));
}
template <class... Args> void info(Args&&... a) {
    if (enabled(Level::info)) write_line(Level::info, detail::cat(std::forward<Args>(a)...));
}
template <class... Args> void warn(Args&&... a) {
    if (enabled(Level::warn)) write_line(Level::warn, detail::cat(std::forward<Args>(a)...));
}
template <class... Args> void error(Args&&... a) {
    if (enabled(Level::error)) write_line(Level::error, detail::cat(std::forward<Args>(a)...));
}

// Shortens a fingerprint/node id for logs: "a1b2c3d4…" (never the full value).
std::string short_id(std::string_view id);

}  // namespace r2r::log
