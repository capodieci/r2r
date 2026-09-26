# The relay

A relay is a server that stores ciphertext for fingerprints, forwards frames
to other relays, gossips peers, peels onion layers and, optionally, sells
storage. It never holds user keys. Any number of implementations may exist;
they are indistinguishable on the wire.

## Implementations

| Directory | Language | Status |
|---|---|---|
| `cpp/` | C++20, Boost.Asio/Beast, OpenSSL, SQLite | **Reference.** Runs the live network. |
| `legacy-v1/` | JS, C, C++, PHP, Python | Retired first generation. Not protocol-compatible; kept as history. |

Add a new one as `relay/<language>/` with its own README, build and tests. It
is accepted as an implementation once it passes the four rungs of the
conformance ladder in `protocol/porting-the-relay.md`, in both smoke-test
positions.

## The protocol

Everything normative lives in `protocol/`:

| File | What it is |
|---|---|
| `R2R-WHITEPAPER.md` (and `.pdf`) | The white paper and complete protocol specification. §19 is the conformance checklist; §17 lists every constant; Appendix A holds hand-checked vectors. Where the paper and the reference code disagree, the code is what the network runs and the paper is corrected. |
| `protocol-vectors.json` | Known-answer vectors generated from the reference code (`cpp/tools/protocol-vectors.cpp`). A port's test suite should assert every entry before opening a socket. |
| `porting-the-relay.md` | What "compatible" covers, the rules ports get wrong, the operator contract, the conformance ladder, and what each language costs. |

`../AI-PORTING-PROMPT.md` packages the above as a single brief for an AI
coding assistant.

## Quick facts

- Transport: WebSocket, path `/r2r`, subprotocol `r2r.v1`, JSON frames.
  Port 8787 plain, 8788 TLS.
- Identity: Ed25519. A relay is its node key; a user is their key pair,
  addressed by a fingerprint of the public key.
- Relays authenticate each other with signed `hello`/`welcome` frames and pin
  keys per address on first *dialled* contact. An address is trusted only after
  this relay has dialled it and found the claimed key there (§11.2). Peer lists
  are accepted from verified relays only.
- Clients prove identity per session with a signature; without one the session
  is anonymous and may only send.
- Storage is a dead drop per fingerprint with a monotonic `seq` cursor, plus an
  append-only journal for wallet history, blobs for voice and video, and a
  storage market settled in USDC on Base.
- Onion routing is the default for stored messages: the relay that files a
  payload never learns who sent it.
