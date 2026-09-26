// R2R relay -- node identity and onion-layer sealing.
//
// A relay has exactly one secret: a 32-byte seed stored at <data-dir>/node.key
// (mode 0600). Everything else is derived from it:
//
//   ed25519 private = seed                     -> signs `hello` frames so peers
//                                                 cannot be impersonated
//   x25519  private = HKDF(seed, "r2r-x25519") -> opens onion layers addressed
//                                                 to this relay
//   node_id         = SHA256("r2r-node-v1" || ed25519_pub)[0..16], hex
//
// The relay never holds any key belonging to a *user*. Message bodies are
// ciphertext produced by clients; the relay cannot read them, and nothing here
// gives it that ability. Onion sealing protects routing metadata only.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "util.hpp"

namespace r2r::crypto {

using util::Bytes;

// Sizes fixed by the primitives we use.
inline constexpr std::size_t kSeedLen = 32;
inline constexpr std::size_t kPubLen = 32;
inline constexpr std::size_t kNonceLen = 12;
inline constexpr std::size_t kTagLen = 16;
inline constexpr std::size_t kSealOverhead = 1 + kPubLen + kNonceLen + kTagLen;  // 61

void init();
std::string openssl_version();

Bytes random_bytes(std::size_t n);
std::string uuid_v4();
// A v2 invite code: "R2R-XXXX-XXXX-XXXX", with two leading hex groups when
// `hint_hex` carries an 8-character IPv4 routing hint. The last three groups
// are 60 bits of entropy in Crockford base32.
std::string invite_code(const std::string& hint_hex = {});
Bytes sha256(const void* data, std::size_t len);
inline Bytes sha256(std::string_view s) { return sha256(s.data(), s.size()); }
void secure_zero(void* p, std::size_t n);

// Domain-separated fingerprint of a public key. Clients derive their identity
// the same way; the relay only ever sees the result.
std::string fingerprint(const Bytes& pubkey);
// The shareable contact address wallets exchange: "R2R_" + base32(pub ‖
// SHA3-256(pub ‖ "R2R")[0..3]) in groups of 8. Empty unless pub is 32 bytes.
std::string contact_address(const Bytes& ed25519_pub);
// The inverse: the ed25519 public key an "R2R_…" address encodes, or nullopt
// when the text is not an address or its checksum does not match. Case and
// separators are ignored, so a hand-typed copy works.
std::optional<Bytes> pubkey_from_contact_address(std::string_view addr);
std::string node_id_from_ed_pub(const Bytes& ed_pub);

class NodeIdentity {
public:
    // Loads <key_path> if present, otherwise generates and persists a new seed.
    static std::optional<NodeIdentity> load_or_create(const std::string& key_path);
    static std::optional<NodeIdentity> from_seed(const Bytes& seed);
    static std::optional<NodeIdentity> generate();

    const std::string& node_id() const { return node_id_; }
    const Bytes& ed_pub() const { return ed_pub_; }
    const Bytes& x_pub() const { return x_pub_; }
    const std::string& ed_pub_b64() const { return ed_pub_b64_; }
    const std::string& x_pub_b64() const { return x_pub_b64_; }

    std::optional<Bytes> sign(std::string_view msg) const;
    // Opens an onion layer addressed to this relay.
    std::optional<Bytes> unseal(const Bytes& blob) const;
    // Opens a v2 multi-recipient layer if one of its slots is ours.
    std::optional<Bytes> unseal_multi(const Bytes& blob) const;

    ~NodeIdentity();
    NodeIdentity(NodeIdentity&&) noexcept;
    NodeIdentity& operator=(NodeIdentity&&) noexcept;
    NodeIdentity(const NodeIdentity&) = delete;
    NodeIdentity& operator=(const NodeIdentity&) = delete;

private:
    NodeIdentity() = default;

    Bytes seed_;    // secret
    Bytes x_priv_;  // secret, derived
    Bytes ed_pub_;
    Bytes x_pub_;
    std::string node_id_;
    std::string ed_pub_b64_;
    std::string x_pub_b64_;
};

bool verify_signature(const Bytes& ed_pub, std::string_view msg, const Bytes& sig);

// HMAC-SHA1. Needed only for TURN's REST credential scheme (RFC 7635 style),
// which specifies SHA-1; it is not used for anything security-critical here.
Bytes hmac_sha1(std::string_view key, std::string_view msg);
Bytes hmac_sha256(std::string_view key, std::string_view msg);

// ---- EVM: what the storage market needs to check a voucher ----------------
// Keccak-256 (the original padding Ethereum uses, not FIPS SHA3-256).
Bytes keccak256(const void* data, std::size_t len);
inline Bytes keccak256(const Bytes& v) { return keccak256(v.data(), v.size()); }
// The white paper §14.4 voucher digest: EIP-191 personal_sign over
// Keccak-256("r2r-voucher-v1" ‖ vault[20] ‖ uint256(chain_id) ‖ payee[20] ‖ uint256(cumulative)).
// `vault` and `payee` are 0x-prefixed hex addresses; empty on bad input.
Bytes evm_voucher_digest(std::string_view vault, std::int64_t chain_id, std::string_view payee,
                         std::int64_t cumulative_micro);
// Recovers the signer of a 65-byte (r ‖ s ‖ v) secp256k1 signature over
// `digest32` and returns its lowercase 0x address. Rejects high-s (the
// malleable half, as the vault contract does) and v outside {0,1,27,28}.
std::optional<std::string> evm_recover_address(const Bytes& digest32, const Bytes& sig65);
// Address of a secp256k1 private key (32 bytes), lowercase 0x hex.
std::optional<std::string> evm_address_of(const Bytes& priv32);
// Signs `digest32` with a secp256k1 private key: 65 bytes r ‖ s ‖ v, low-s,
// v ∈ {27, 28}. Used by the probe to mint test vouchers; the relay only
// recovers.
std::optional<Bytes> evm_sign(const Bytes& priv32, const Bytes& digest32);

// Anonymous sealed box: ephemeral X25519 -> HKDF-SHA256 -> AES-256-GCM.
// Layout: version(1) || eph_pub(32) || nonce(12) || ciphertext || tag(16)
std::optional<Bytes> seal(const Bytes& recipient_x_pub, const void* plaintext, std::size_t len);
inline std::optional<Bytes> seal(const Bytes& recipient_x_pub, std::string_view pt) {
    return seal(recipient_x_pub, pt.data(), pt.size());
}
std::optional<Bytes> unseal(const Bytes& our_x_priv, const Bytes& our_x_pub, const Bytes& blob);

// Multi-recipient onion layer (v2). The plaintext is encrypted once under a
// fresh 32-byte key K; K is sealed (above) to each of 1..kMaxSlots candidate
// relays, any one of which can open the layer:
//   0x02 ‖ n ‖ n × seal(candidate_i, K)[93] ‖ nonce[12] ‖ AES-256-GCM(K, pt, aad) ‖ tag[16]
// with aad = the header up to and including the last slot, so slots cannot be
// swapped or stripped without breaking the tag.
inline constexpr std::uint8_t kMultiVersion = 0x02;
inline constexpr std::size_t kMaxSlots = 3;
inline constexpr std::size_t kSlotLen = kSealOverhead + kPubLen;  // 93: a sealed 32-byte key
inline constexpr std::size_t kMultiMin = 2 + kSlotLen + kNonceLen + kTagLen;
std::optional<Bytes> seal_multi(const std::vector<Bytes>& recipient_x_pubs, const Bytes& plaintext);
std::optional<Bytes> unseal_multi(const Bytes& our_x_priv, const Bytes& our_x_pub, const Bytes& blob);

}  // namespace r2r::crypto
