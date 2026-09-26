// R2R relay -- layered (onion) routing, layer format v2.
//
// Each layer is a multi-recipient sealed box (crypto::seal_multi): it names
// 1..3 candidate relays for its position, and whichever of them receives it
// can open it. Opening reveals exactly one of two things:
//
//   routing layer   0x01 ‖ n ‖ n × (len8 ‖ "host:port") ‖ inner layer
//                   -- the candidates for the NEXT position, tried in order,
//                      and the opaque layer for them
//   terminal layer  0x02 ‖ len16be ‖ JSON {"to","id","hint"?} ‖ body
//                   -- store `body` for "to" (a fingerprint, optionally
//                      "fp@home": when home is another relay, forward there)
//
// A relay therefore learns its predecessor (the socket), the candidate set
// for the next position, and nothing else -- not the sender, not the
// recipient (unless it is a terminal), not the route length. Alternatives
// let a route survive relays that are down without the sender re-sending.
// The body is still end-to-end ciphertext; onion sealing protects metadata.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "util.hpp"

namespace r2r::onion {

inline constexpr std::uint8_t kRouting = 0x01;
inline constexpr std::uint8_t kTerminal = 0x02;
inline constexpr std::size_t kMaxLayers = 8;

struct Terminal {
    std::string to;         // recipient fingerprint
    std::string home;       // canonical "host:port" of its relay, or empty
    std::string msg_id;     // uuid, used for de-duplication
    std::string from_hint;  // opaque sender token chosen by the client; may be empty
    util::Bytes body;       // ciphertext for the recipient
};

struct Layer {
    bool terminal{false};
    std::vector<std::string> next;  // canonical "host:port" candidates when !terminal
    util::Bytes inner;              // multi-sealed blob for `next`
    Terminal deliver;               // meaningful when terminal
};

// Parses one decrypted layer. `max_body` bounds the terminal payload.
std::optional<Layer> parse(const util::Bytes& plaintext, std::size_t max_body);

struct Hop {
    std::string address;     // "host:port" of the relay
    std::string x25519_b64;  // its sealing key, from peers.json
};

// Builds the outermost blob. `sets[i]` holds the 1..3 candidates for route
// position i; the last set holds the terminal candidates (recipient's relay
// first). Used by clients and r2r-probe; the relay itself never builds routes.
std::optional<util::Bytes> build(const std::vector<std::vector<Hop>>& sets,
                                 const Terminal& terminal);

}  // namespace r2r::onion
