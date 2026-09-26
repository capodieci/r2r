# Prompt: implement the R2R relay in another language

Copy everything below the line into your AI coding assistant, together with
the files it names. Fill in the two placeholders. The prompt assumes the
assistant can read files in this repository and run commands.

---

You are implementing a new, wire-compatible version of the **R2R relay** in
**{LANGUAGE}**. The result must be indistinguishable from the reference relay
by other relays and by the wallet. The work is done when it passes the
conformance ladder described below in both smoke-test positions. Work in
`relay/{language}/` of this repository.

## What the relay is

R2R is a private messaging network with no central server. A relay is a
dead-drop server: it stores ciphertext for user fingerprints, forwards frames
that belong to other relays, gossips a signed peer list, peels onion layers,
and optionally sells storage. It never holds user keys; the only secret it
owns is its own Ed25519 node seed. Users are Ed25519 key pairs addressed by a
fingerprint; relays learn only the recipient's fingerprint of a payload.

## Read these first, in this order

1. `relay/protocol/R2R-WHITEPAPER.md`. This is the normative specification.
   Read §2 through §4 for the model, then §6 through §13 for every frame and
   rule, §16 for the HTTP routes, §17 for every constant and timer, §18 for
   the threat model, and **§19, the conformance checklist, which is the list
   of things a relay MUST and SHOULD do.** §20 lists the reference
   implementation's quirks that the network currently depends on. Where the
   paper and the reference code disagree, the code is what the network runs;
   note the disagreement and follow the code.
2. `relay/protocol/porting-the-relay.md`. It says what "compatible" covers,
   which rules ports most often get wrong, the operator contract (flags,
   environment, files, signals) and the conformance ladder.
3. `relay/protocol/protocol-vectors.json`. Known-answer vectors generated from
   the reference code, with notes beside each value. Every entry is
   deterministic from its stored inputs.
4. The reference code in `relay/cpp/src/`, as the final word on any detail.
   The map from specification section to source file is in
   `porting-the-relay.md`. `relay/cpp/src/protocol.hpp` holds every frame type
   name and error code; `relay/cpp/src/hub.cpp` is the frame dispatcher.
5. `relay/cpp/tools/probe.cpp`, the reference client, and
   `relay/cpp/scripts/smoke-test.sh`, the black-box test you must pass.

## Scope

**In scope, must match exactly:** encodings and primitives (§3); identities,
fingerprints, `R2R_…` addresses and proofs of possession (§4); transport,
framing, limits and session state (§6); every client frame from `hello`
through the `admin_*` frames (§7, §13); dead drops, `seq` cursors, quotas,
TTL, journal, blobs and pools (§8); addressing, forwarding, the pending queue,
pointers, deposit and collect (§9); onion layers, sealed boxes and relay
processing, byte for byte (§10); the relay handshake, address verification,
pinning, gossip, `peers.json`, seeds and timers (§11); invite codes,
claiming, activation and revocation (§12); the storage market frames (§14; a
port may answer `market_off`); and the HTTP routes `/peers.json`,
`/node.json`, `/status.json`, `/health`, `/invite/*` and `/assets/` (§16).

**Out of scope, free to differ or omit:** the doorway web site, the admin
console, the metrics sync, the settlement contract, and the SQLite schema.
Store data any way you like as long as the operator commands exist.

**The operator contract must hold** so that `install.sh`, the systemd unit and
the smoke test work unchanged: the flags, environment variables, data-directory
files (`node.key`, `peers.json`, `genesis-invites.txt`) and signals listed in
`porting-the-relay.md` under "The operator contract".

## Rules you must not get wrong

These are the rules where nothing local breaks when they are wrong, only the
network does. §19.1 of the white paper is the full list.

- **An `err` frame is terminal.** Never answer an error with an error.
- **`seq` is the only cursor.** `fetch` returns monotonically increasing `seq`
  values and a `cursor` in `fetch_done`. Timestamps are not usable.
- **Canonical strings are exact bytes.** The four signing strings
  (`r2r-hello-v1`, `r2r-client-v1`, `r2r-pointer-v1`, `r2r-collect-v1`) join
  their fields with a single `\n`, decimal timestamps, no trailing newline.
  Fingerprints are 64 lowercase hex characters. Base64 is standard, padded on
  output; the decoder accepts unpadded and URL-safe input but rejects non-zero
  leftover bits.
- **Identity is proved, never asserted.** A `hello` without a valid signature
  leaves the session anonymous; `fetch`, `ack`, `deposit`, journal and owner
  frames must then refuse with `not_authorised`.
- **Claiming an invite is atomic:** burn the code, register the identity and
  mint exactly three successors in one transaction, or do nothing.
- **Verified means dialled.** A signed relay `hello` on an inbound connection
  proves that the peer holds a key. It proves nothing about the address it
  advertises. An address becomes verified only when *your* relay dialled it
  and the node answering there proved its key. Only verified addresses are
  published on `/peers.json`, exported in gossip, counted as active or used
  as rendezvous nodes. An inbound claim is recorded unverified and dialled
  later by the maintain timer, at most two such verification dials per tick.
- **Peer lists come from verified relays only.** A `peers` frame from a
  client is `not_authorised`; from an unverified relay session it is ignored.
  One session may add at most 64 new addresses. Never dial an address just
  because a session told you about it.
- **Pins are set by your own dial, never by gossip or an inbound hello.**
  A key on an unverified entry is a hint. It must never cause a handshake to
  be rejected and it is replaced by whatever the address proves when dialled.
  A key on a verified entry is the pin; a different key for that address is
  rejected with code 1008.
- **Refuse non-public addresses everywhere:** loopback, RFC 1918, link-local,
  carrier-grade NAT, unspecified, multicast, documentation and reserved
  ranges, their IPv6 equivalents and IPv4-mapped forms. This applies to
  `peers.json`, `advertise` in a hello, gossip entries, the client's
  `fingerprint@host:port` destinations, and hostnames after DNS resolution.
  Provide `--allow-private-peers` for test benches only.
- **Pointers and presence are gated.** Accept a pointer only from a verified
  relay session, and only when the address it names is a peer your relay has
  verified with that node id and key. Answer `watch` only for sessions that
  proved an identity.
- **Vouchers are verified before storage is extended.** Rebuild the §14.4
  digest (Keccak-256 with the original padding, EIP-191 prefix), recover the
  secp256k1 signer (low-s only), and require it to equal the rental's payment
  key. Refuse vouchers when no vault address is configured.
- **Onion silence.** A relay that accepts a layer sends nothing back; only
  failures travel back. The layer tag covers the whole slot header.
- **Gossip only on the first handshake of a connection**, so a repeated
  `hello` cannot be used as an amplifier.
- **Limits are behaviour:** 1 MiB frame cap, 40 frames/s with a burst of 120
  per connection, 256 KiB default payload, the clock-skew windows in §17.

## The conformance ladder

Climb it in order. Do not start a rung before the previous one is green.

1. **Known-answer vectors.** Load `relay/protocol/protocol-vectors.json` in
   your unit tests and assert every entry: key derivations, fingerprints,
   node ids, the canonical strings and their signatures, the accepted and
   rejected `hello` frames, HMAC and TURN credentials, the sealed box with its
   intermediate values, the multi-recipient layer, both onion routes and what
   each hop must see, and the `parse_target` / `parse_address` cases. Read the
   `notes` fields; they record the things a port author would not guess.
2. **The smoke test, in both positions.** Build the reference relay once
   (`relay/cpp/README.md`), then run from `relay/cpp/`:

   ```sh
   RELAY_B=/path/to/your/relay ./scripts/smoke-test.sh build   # your relay as the peer and storage node
   RELAY_A=/path/to/your/relay ./scripts/smoke-test.sh build   # your relay as the node clients talk to
   ```

   Every check must pass in both positions. `KEEP=1` leaves the relay logs
   behind for inspection. The test drives the binaries through the operator
   contract, so if a flag or file is missing the test tells you.
3. **Live interop.** Run your relay with `--seed` pointing at a reference
   relay on a private network. Within a minute `peers.json` on both sides
   must list the other as `"verified": true`; sends in each direction must be
   collectable on the other; leave it running for an hour and confirm gossip,
   pings, pruning and the five-minute `peers.json` rewrite keep behaving.
4. **The wallet.** Point `wallets/r2r-web/dist/` at your relay: claim an
   invite, exchange messages with someone on a reference relay, place a call,
   restore from the journal in a second browser.

## How to work

- Start from the vectors and the crypto layer, then the session layer and
  client frames, then storage, then routing and onion, then the peer mesh,
  then invites and the market. This is the order in which each piece can be
  tested against the reference before the next depends on it.
- Keep a `CONFORMANCE.md` in your directory: one line per §19 checklist item,
  with a pointer to the test that proves it. Unchecked items are the backlog.
- When you find a place where the paper and the reference code disagree,
  follow the code and record the discrepancy in `CONFORMANCE.md` under
  "Spec corrections", so the paper can be fixed.
- Do not invent extensions. A frame type the reference does not know is
  answered with `unknown_type`, and the network gains nothing from a relay
  that only speaks to itself.
- Ship one static binary per architecture if the language allows it, named
  `r2r-relay`, plus `r2r-probe` if you also port the client. `install.sh`
  picks binaries by `uname -m`.

## Deliverables

- `relay/{language}/README.md`: how to build, test and run; which optional
  parts (doorway, admin console, market) are implemented.
- The implementation, with unit tests that assert every vector.
- `CONFORMANCE.md` with §19 fully ticked and the smoke test green in both
  positions, with the exact commands used.
- No new dependencies on services outside the relay process. A relay is one
  process and one data directory.
