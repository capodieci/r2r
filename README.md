# R2R

R2R is a private messaging network with no central server. Every message is
end-to-end encrypted before it leaves the sender's device and is carried by a
mesh of small, interchangeable **relays**: dead-drop servers that hold
ciphertext they cannot read, forward what belongs to other relays, and gossip
a signed peer list so the network can find itself. Users have no accounts and
no phone numbers; a user is an Ed25519 key pair. The client application is
called the **wallet**.

The protocol is public and the reference implementations are here. Anyone may
run a relay, write a relay in another language, or build a wallet. A relay or
wallet that speaks the protocol correctly joins the network; one that does not
is refused by the relays it talks to.

## Layout

```
relay/
  protocol/        The protocol: white paper (normative spec), test vectors,
                   porting guide.
  AI-PORTING-PROMPT.md
                   A complete prompt for an AI coding assistant asked to
                   implement the relay in another language.
  cpp/             The reference relay (C++). This is what the live network
                   runs. Includes the install script, systemd unit, smoke test,
                   cross-build toolchain and the "doorway" web site it serves.
  legacy-v1/       The previous, retired relay generation, kept for reference.
  <language>/      Future implementations (go/, rust/, python/ ...). Each must
                   pass the conformance ladder in relay/protocol/porting-the-relay.md.

wallets/
  r2r-web/         The reference wallet: a single-page browser application
                   (chat, calls, mail, groups, storage market, setup cards).
  docs/            Wallet design notes, change requests and test reports.
  <name>/          Other wallets. See wallets/README.md for what a wallet
                   can rely on the relay for.

contracts/         R2RStorageVault: the on-chain settlement contract for the
                   storage market (Solidity, deployed on Base).
docs/              System-level design notes that span relay, wallet and
                   contract.
```

## Start here

- **Understand the system:** `relay/protocol/R2R-WHITEPAPER.md`. Sections 2
  through 4 explain the model; 6 through 13 are the wire protocol; 19 is the
  conformance checklist.
- **Run a relay:** `relay/cpp/README.md` and `relay/cpp/docs/install-a-relay.md`.
  One static binary, one script, one systemd unit.
- **Port the relay:** `relay/protocol/porting-the-relay.md`, then
  `relay/AI-PORTING-PROMPT.md` if you are working with an AI assistant.
- **Build a wallet:** `wallets/README.md`, then `wallets/r2r-web/WALLET-GUIDE.md`.

## Security reports

Test against your own relays, or against the public seeds listed in
`relay/cpp/src/config.cpp` if the test cannot harm other users' traffic.
Report what you find to the maintainers before publishing it. Reports are
welcome and are answered; the peer-table verification rules in white paper
§11 came out of one.

## License

See `LICENSE`.
