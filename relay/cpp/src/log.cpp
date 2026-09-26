#include "log.hpp"

#include <atomic>
#include <cstdio>
#include <mutex>

#include "util.hpp"

namespace r2r::log {
namespace {
std::atomic<Level> g_level{Level::info};
std::mutex g_mu;
}  // namespace

void set_level(Level lvl) { g_level.store(lvl, std::memory_order_relaxed); }
Level get_level() { return g_level.load(std::memory_order_relaxed); }
bool enabled(Level lvl) { return static_cast<int>(lvl) >= static_cast<int>(get_level()); }

const char* level_name(Level lvl) {
    switch (lvl) {
        case Level::trace: return "TRACE";
        case Level::debug: return "DEBUG";
        case Level::info:  return "INFO ";
        case Level::warn:  return "WARN ";
        case Level::error: return "ERROR";
        case Level::off:   return "OFF  ";
    }
    return "?????";
}

std::optional<Level> level_from_string(std::string_view s) {
    if (util::iequals(s, "trace")) return Level::trace;
    if (util::iequals(s, "debug")) return Level::debug;
    if (util::iequals(s, "info")) return Level::info;
    if (util::iequals(s, "warn") || util::iequals(s, "warning")) return Level::warn;
    if (util::iequals(s, "error")) return Level::error;
    if (util::iequals(s, "off") || util::iequals(s, "none")) return Level::off;
    return std::nullopt;
}

void write_line(Level lvl, const std::string& msg) {
    const std::string ts = util::iso8601(util::now_unix());
    std::lock_guard<std::mutex> lock(g_mu);
    // Diagnostics go to stderr so that stdout stays reserved for a command's
    // actual output -- `r2r-probe whoami` must print a fingerprint and nothing
    // else. systemd captures both streams into the journal regardless.
    std::fprintf(stderr, "%s %s %s\n", ts.c_str(), level_name(lvl), msg.c_str());
    std::fflush(stderr);
}

std::string short_id(std::string_view id) {
    if (id.empty()) return "-";
    if (id.size() <= 8) return std::string(id);
    return std::string(id.substr(0, 8)) + "..";
}

}  // namespace r2r::log
