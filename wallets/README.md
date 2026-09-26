# Wallets

The wallet is the client. It holds the user's identity key in a
PIN-encrypted local vault, encrypts and decrypts everything, and talks to
relays over one JSON-over-WebSocket protocol. Relays never see a key or a
plaintext. Anyone can build a wallet: a relay does not care which client
connects, only that it speaks the protocol.

## Wallets in this repository

| Directory | What it is |
|---|---|
| `r2r-web/` | The reference wallet: a single-file browser application (`dist/R-2-R Chat & Calls.html`) with chat, group chat, mail, voice and video calls, journal restore, invites, the owner panel, the storage market and setup cards. `app/` holds the sources, `WALLET-GUIDE.md` the design, `RELAY-SPEC.md` the wallet-side summary of the protocol. `dist/Setup Card Forge.html` prints setup cards. |
| `docs/` | Change requests, test reports and the brief for the client app. |

Add another wallet as `wallets/<name>/` with its own README. Native apps,
command-line clients and bots are all wallets in this sense.

## What a wallet can rely on the relay for

The white paper (`../relay/protocol/R2R-WHITEPAPER.md`) is the specification;
§5 describes the wallet's local model and §15 the behaviours users expect.
`../relay/cpp/tools/probe.cpp` is a minimal reference client that exercises
every frame from a shell. What the relay offers, in one page:

- **Identity without accounts.** An Ed25519 key pair is the identity. The
  fingerprint is a hash of the public key; the shareable `R2R_…` address
  encodes the key with a checksum. A session proves the key with a signature
  in `hello`; an unproven session is anonymous and may only send. (§4, §7)
- **Dead drops.** Anyone can leave a payload for a fingerprint on any relay.
  The owner fetches with a monotonic `seq` cursor and acknowledges. Payloads
  are opaque bytes with a TTL and a per-user quota. Onion routing, on by
  default in the reference wallet, hides the sender from the filing relay.
  (§8, §9, §10)
- **Push delivery and presence.** A subscribed session receives new drops
  live; `watch` reports whether a contact is online. (§7)
- **Journal.** An append-only, encrypted history per identity, so a new
  device restores everything from the key alone, and a printed setup card
  plus a PIN can recreate the identity without writing the seed down. (§5, §8)
- **Blobs.** Content-addressed storage for voice and video messages above the
  frame limit, fetched over HTTP with the same signed proof. (§8)
- **Calls.** WebRTC signalling relayed between sessions, across relays, and
  STUN/TURN credentials minted by the relay. (§7, §15)
- **Cross-relay delivery.** Address `fingerprint@host:port` to reach an
  identity homed elsewhere; the relay forwards, parks what it cannot deliver,
  and leaves pointers so the recipient can collect. (§9)
- **Invites.** Joining a relay is invite-gated. Claiming a code registers the
  identity and mints three locked successors that unlock once the member is
  active. Relays with `--open-registration` skip the code. (§12)
- **Ownership.** A relay's owner, identified by fingerprint, manages quotas
  and invites from inside the wallet through the `admin_*` frames. (§13)
- **Storage market.** A wallet can rent replica space on other relays and pay
  with signed USDC vouchers settled through `../contracts/`. The relay holds
  no chain keys. (§14)

## What a wallet must do itself

Everything that touches plaintext or keys: key generation and the scrypt
PIN vault (§5.2), envelope encryption between contacts (§5.7), group keys,
sealing onion layers (§10), mail threading, call media, local history and
retention. The relay stores and moves bytes; the wallet gives them meaning.

## Building one

1. Assert the vectors in `../relay/protocol/protocol-vectors.json` for the
   wallet-side primitives (fingerprints, `R2R_…` addresses, client proof
   strings, sealed boxes, onion layers).
2. Run a reference relay locally (`../relay/cpp/README.md`, or the smoke test
   ports) and drive it with your client frame by frame, comparing against
   `probe.cpp`.
3. Exchange messages with the reference wallet on the same relay, then with a
   contact on a different relay, then through an onion route.
4. Follow the change-request format in `r2r-web/WALLET-GUIDE.md` §9 when the
   relay needs to change for your wallet; that is how the reference wallet
   and relay have evolved together.
