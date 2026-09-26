# Federating the existing relay

The problem that started the rewrite: relays do not talk to each other, so a
message for someone whose home relay is elsewhere sits in the wrong queue
forever. This directory shows how small that fix actually is on the relay you
already have.

Everything here has been run. `node --version` 22.x.

## Option 1 — no server change at all

`test-zero-change.js`

The existing `send` handler accepts any `to` from any authenticated user and
queues it locally. So the sender's *client* can simply open a second connection
to the recipient's relay and deliver there. Bob receives it live; nothing on the
server changes.

```
$ node test-zero-change.js
relay B acknowledged: {"type":"sent","id":"deadbeef","queued":false}
RESULT: bob received it -> {"type":"msg", ... "payload":"ciphertext-for-bob"}
cross-relay delivery WORKS with zero server changes.
```

What it costs: the sender connects to the recipient's relay, so that operator
sees the sender's IP, and it fails when a client cannot reach that relay
directly (restrictive network, relay reachable only from other relays).

## Option 2 — a server-side hop, 46 lines

`federation.patch` (apply to `relay-server.js`), result in
`relay-server-federated.js`, tests in `test-federated.js`.

The sender only ever talks to its own relay. Add a `relay` hint to the existing
`send` frame and the relay hands the message over by HTTP POST:

```json
{ "type":"send", "to":"<pub>", "id":"...", "payload":"...", "relay":"1.2.3.4:8787" }
```

Three insertions:

1. a relay keypair (generated once into `DATA_DIR/relay.key`) and a
   `forwardTo()` helper — the relay authenticates to its peer with the same
   `?pub&ts&sig` scheme already used for clients;
2. a `POST /forward` route that validates and `qPush`es, delivering live if the
   recipient is connected;
3. four lines in the `send` handler that take the hint when it is present.

```
$ node test-federated.js
  ok   live message crossed A -> B while Bob was online
  ok   sender identity preserved across the hop
  ok   message queued on Bob's relay and flushed when he reconnected
  ok   without a relay hint the old local-queue behaviour is untouched
passed 4, failed 0
```

The last check matters: a `send` with no `relay` hint behaves exactly as before,
so this is additive and cannot break existing clients.

## What neither option gives you

- **Automatic peer discovery.** Both need the client (option 1) or the sender
  (option 2) to know the recipient's relay address. With a fixed set of seed
  nodes that is a contact-card field, not a protocol.
- **Multi-hop metadata privacy.** Relay A learns that this sender is messaging
  someone on relay B. Hiding that needs onion routing.
- **Delivery when the destination relay is down.** Option 2 fails the POST and
  reports `forwarded:false`; retrying is left to the sender.

## Storage, separately

Worth knowing before this node becomes the busy one — these are independent of
federation:

- `qPush` re-reads and re-writes the recipient's entire queue JSON for every
  message. A full 500-message queue is ~680 KB; 200 messages into a full queue
  measured **934 ms of CPU** before any disk I/O. It is cheap for short queues
  and degrades exactly when someone has been offline a while.
- `fs.writeFileSync` on the queue is not atomic — a crash mid-write truncates
  that recipient's whole queue.
- `acctUsed()` and `nextSeq()` `readdir` + `stat` every journal file on every
  `/journal` POST, so each new event costs one syscall per existing event.

Node 22 ships `node:sqlite` (experimental but functional), so moving the queue
and journal to a database is possible without giving up the zero-dependency
property. That is a contained change to three or four functions, not a rewrite.
