# Project notes

## Backlog
- **Pin `VAULT_ADDR`** in `app/core.js` when the R2RStorageVault contract deploys (then remove the "do not deposit" warning; add real chain-registry checks per the ABI).
- **Retention policies** — per-surface pruning (chat 3 mo / mail forever / etc.), client-side pruning + journal compaction.
- **IndexedDB migration** for larger local attachment storage.
- TURN escalation for group calls.

## Done (recent)
- **Relay-hosting instructions refreshed** (2026-09-24, relay-side patch of the template + dist, no
  rebundle available on the relay host): the setup page "Set up your own relay" steps and the Settings
  "Run your own relay" block now describe the one-command install (curl the four files from any
  relay's /assets, `sudo ./install.sh SERVER-IP:8787`, genesis invites, `--owner-add`) instead of the
  hand-built systemd unit. Carry this into the design project before the next rebundle.
- **Onion v2 + scrypt** (2026-09-23): multi-candidate layers, Extra privacy (5 positions), freshness
  filter; scrypt vault/locator/protected-invite KDF, PIN policy, brain-wallet keys refused.
- **Invite activation** (2026-09-23): locked member codes, `vouchreq`/auto-`vouch`, `invite_status`,
  inviter auto-added as contact; error codes kept in one-shot rejections. Bundle template edits must
  use the `sc-camel-on-*` attribute form (the template is a transformed copy of the dc.html).
- **Onion routing in the wallet** (2026-09-23): default-on, Settings → Privacy toggle; pure-JS
  seal (AES-256-GCM/HKDF) byte-identical to the relay; anonymous per-message entry sockets;
  dack-based completion with 15-min direct fallback. Bundle rebuilt by replacing the core.js
  manifest entry + template (no super_inline_html available on the relay host).
- **Protocol v2 migration** (clean break, v1 stack deleted): fingerprint ids, hello-frame auth (`r2r-client-v1`), `X-R2R-Auth` header, UUID v4 message ids, invite-gated registration (+ setup-page "Use an invite code"), push/fetch/ack delivery, client-side encrypted delivery receipts (`dack`), locate/mail_at/deposit mail gathering, journal over frames, node_id/base-path relay meta, owner admin via frames (no admin key), storage market (secp256k1 + keccak + EIP-191 vouchers in `app/eth.js`, per-rental payment keys, replicate→audit→voucher cycle), `x25519` field sent on hello/invite_claim.
- Group chat/calls, multi-recipient mail, security round (earlier).

## Conventions
- Wallet = `R-2-R Chat & Calls.dc.html`, core logic in `app/core.js`, market/eth crypto in `app/eth.js`. Protocol: relay repo (`~/r2r-relay`) is authoritative; `RELAY-SPEC.md` here is the wallet-side v2 summary; `WALLET-GUIDE.md` is the hand-off doc for relay devs.
- The five v1 reference relays and `app/relay-src.js` are RETIRED and deleted — the wallet links to any relay's `/downloads` page instead of embedding sources.
- Setup cards: `R2RSC1:<cardKeyHex64>:<relay[,relay…]>` (unchanged, 2 fields); identity lives in a PIN-derived locator account's journal. Forge = `Setup Card Forge.dc.html`. Wire constants: `r2r-client-v1` hello sign prefix, `r2r-collect-v1` deposit auths, `r2r-voucher-v1` vouchers, envelope = b64(senderPub‖nonce‖box), r2r1_* storage keys.
- Always rebundle `dist/` (super_inline_html) after wallet/forge changes.
