// R2R relay -- wire protocol constants and small frame helpers.
//
// Every frame is a JSON text frame with a "t" (type) field. Binary payloads
// travel base64-encoded inside "body"/"blob" so the same protocol works from a
// browser, a desktop client or another relay without content negotiation.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace r2r::proto {

inline constexpr int kVersion = 1;
inline constexpr const char* kSubprotocol = "r2r.v1";

// Frame types.
inline constexpr const char* kHello = "hello";
inline constexpr const char* kWelcome = "welcome";
inline constexpr const char* kSend = "send";
inline constexpr const char* kSent = "sent";
inline constexpr const char* kDrop = "drop";
inline constexpr const char* kFetch = "fetch";
inline constexpr const char* kFetchDone = "fetch_done";
inline constexpr const char* kAck = "ack";
inline constexpr const char* kOnion = "onion";
inline constexpr const char* kPing = "ping";
inline constexpr const char* kPong = "pong";
inline constexpr const char* kPeersReq = "peers_req";
inline constexpr const char* kPeers = "peers";
inline constexpr const char* kInviteClaim = "invite_claim";
inline constexpr const char* kInviteOk = "invite_ok";
// A member's own invite codes unlock once the member is active: it has
// received real traffic, and the identity that invited it has vouched for it
// (the inviter's wallet does so after a two-way chat).
inline constexpr const char* kVouch = "vouch";
inline constexpr const char* kVouchOk = "vouch_ok";
inline constexpr const char* kInviteStatus = "invite_status";
inline constexpr std::int64_t kActivationReceived = 3;
inline constexpr const char* kSubscribe = "subscribe";
inline constexpr const char* kMail = "mail";  // "you have N payloads waiting"
inline constexpr const char* kQuota = "quota";  // storage allowance and usage

// --- mail pointers: discovery of mail parked on other relays ----------------
// A relay that stores a payload for an identity it does not home emits a
// signed pointer ("this relay holds mail for X") toward X's home relay when
// known, else to X's rendezvous relays. `locate` lets the identity's own
// session ask where its mail waits; `mail_at` is the live nudge.
inline constexpr const char* kPointer = "pointer";  // relay-to-relay
inline constexpr const char* kLocate = "locate";    // client asks
inline constexpr const char* kLocated = "located";  // the answer
inline constexpr const char* kMailAt = "mail_at";   // push to a live session

// --- safe deposit: authorized collection of parked mail ---------------------
// The identity signs, per holding relay, a single-use instruction: "whoever
// presents this may collect my stored payloads there, and (collect-delete)
// you may delete after handover". The instruction names the holder but never
// the collector, so gathering mail does not reveal where the identity lives.
inline constexpr const char* kDeposit = "deposit";          // client -> its relay
inline constexpr const char* kDepositOk = "deposit_ok";
inline constexpr const char* kCollect = "collect";          // collector -> holder
inline constexpr const char* kCollectItem = "collect_item"; // holder -> collector
inline constexpr const char* kCollectDone = "collect_done";

// --- live session: calls and presence --------------------------------------
// `sig` carries opaque WebRTC signalling (offer, answer, ICE candidates)
// between two clients. The relay forwards it and never inspects it; once the
// peer connection is up, audio and video flow directly between the two
// clients and never touch a relay.
inline constexpr const char* kSig = "sig";
inline constexpr const char* kIce = "ice";            // ask for STUN/TURN servers
inline constexpr const char* kWatch = "watch";        // subscribe to presence
inline constexpr const char* kPresence = "presence";  // both directions

// --- journal: the client's own encrypted history ---------------------------
// Append-only, per identity. A client signing in from a new browser replays it
// to rebuild its message history. Entries are ciphertext; the relay stores and
// counts them, and cannot read them.
inline constexpr const char* kJournalAppend = "journal_append";
inline constexpr const char* kJournalRead = "journal_read";
inline constexpr const char* kJournal = "journal";
inline constexpr const char* kJournalOk = "journal_ok";

// --- storage market: rentals and settlement vouchers ------------------------
// A rental reserves bytes from the relay's market pool for the session's
// identity; the reservation is real quota, never oversold. Payment is a
// cumulative micro-USDC voucher (EIP-191 signed by the wallet's payment key)
// that the relay stores verbatim and the operator redeems on-chain -- the
// relay itself holds no chain keys and never verifies the signature. See
// docs/settlement-design.md.
inline constexpr const char* kRent = "rent";
inline constexpr const char* kRentOk = "rent_ok";
inline constexpr const char* kVoucher = "voucher";
inline constexpr const char* kVoucherOk = "voucher_ok";

// --- relay administration, for the owner's wallet --------------------------
// Authorised by the same identity proof every client sends; the relay checks
// the fingerprint against its owners table. There is no separate admin
// password, so there is nothing to copy around or leak.
inline constexpr const char* kAdminAccounts = "admin_accounts";
inline constexpr const char* kAdminSetQuota = "admin_set_quota";
inline constexpr const char* kAdminInvites = "admin_invites";
inline constexpr const char* kAdminRevokeInvite = "admin_revoke_invite";
inline constexpr const char* kAdminListInvites = "admin_list_invites";
inline constexpr const char* kAdminSetTtl = "admin_set_ttl";
inline constexpr const char* kAdminSearchAccounts = "admin_search_accounts";
inline constexpr const char* kAdminDeleteAccount = "admin_delete_account";
inline constexpr const char* kAdminSetAdvertise = "admin_set_advertise";
inline constexpr const char* kAdminListRentals = "admin_list_rentals";
inline constexpr const char* kAdminListVouchers = "admin_list_vouchers";
inline constexpr const char* kAdminOk = "admin_ok";

inline constexpr const char* kErrNotOnline = "not_online";
inline constexpr const char* kError = "err";
inline constexpr const char* kBye = "bye";

// Error codes carried in `err` frames.
inline constexpr const char* kErrBadFrame = "bad_frame";
inline constexpr const char* kErrBadField = "bad_field";
inline constexpr const char* kErrTooBig = "too_big";
inline constexpr const char* kErrRateLimited = "rate_limited";
inline constexpr const char* kErrNotAuthorised = "not_authorised";
inline constexpr const char* kErrUnknownType = "unknown_type";
inline constexpr const char* kErrNoRoute = "no_route";
inline constexpr const char* kErrQuota = "quota";
inline constexpr const char* kErrInviteInvalid = "invite_invalid";
inline constexpr const char* kErrInviteUsed = "invite_used";
inline constexpr const char* kErrInviteRevoked = "invite_revoked";
inline constexpr const char* kErrInviteLocked = "invite_locked";
inline constexpr const char* kErrAlreadyRegistered = "already_registered";
inline constexpr const char* kErrMarketOff = "market_off";
inline constexpr const char* kErrMarketFull = "market_full";
inline constexpr const char* kErrInternal = "internal";
inline constexpr const char* kErrLooped = "hop_limit";

// The exact bytes a relay signs inside its `hello`, proving it holds the
// ed25519 key that peers.json pins for its node id.
std::string hello_signing_string(std::string_view node_id, std::string_view advertise,
                                 std::int64_t ts, std::string_view nonce);

// The bytes a *client* signs to prove it holds the key its fingerprint is
// derived from. Without this a fingerprint is only a claim, and anyone could
// collect anyone else's mail by asserting it.
std::string client_auth_string(std::string_view fingerprint, std::int64_t ts,
                               std::string_view nonce);

// The bytes a relay signs inside a mail pointer, binding "I hold mail for
// this fingerprint" to its pinned node key so a pointer cannot be forged.
std::string pointer_signing_string(std::string_view fingerprint, std::string_view address,
                                   std::int64_t ts);

// The bytes an identity signs to authorize collection of its payloads from
// one specific holding relay. Holder-bound and single-use (the holder burns
// the nonce), so a captured authorization cannot be replayed; deliberately
// silent about who collects.
std::string collect_signing_string(std::string_view fingerprint, std::string_view holder,
                                   std::string_view scope, std::int64_t ts,
                                   std::string_view nonce);

nlohmann::json make_error(std::string_view code, std::string_view message,
                          std::string_view ref = {});

// "fingerprint" or "fingerprint@host:port" -> the two parts.
struct RouteTarget {
    std::string fingerprint;
    std::string relay;  // empty when the target is local / unspecified
    bool valid{false};
};
RouteTarget parse_target(std::string_view target);

}  // namespace r2r::proto

namespace r2r {
struct Config;
// Builds the iceServers list a client needs to place a call. With a TURN
// secret configured the credentials are derived per request and expire; the
// client must ask again before they do, which is what `ttl` is for.
nlohmann::json build_ice_servers(const Config& cfg, std::string_view identity);
}  // namespace r2r

namespace r2r::proto {

}  // namespace r2r::proto
