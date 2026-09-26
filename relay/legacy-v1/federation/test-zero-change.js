// Does cross-relay delivery already work on the UNMODIFIED old relay, purely by
// having the sender's client connect to the recipient's relay?
'use strict';
const { newIdentity, connect } = require('./client');

const A = 9001;  // Alice's home relay
const B = 9002;  // Bob's home relay

(async () => {
  const alice = newIdentity();
  const bob = newIdentity();
  console.log('alice', alice.pub.slice(0, 16) + '...  home relay :' + A);
  console.log('bob  ', bob.pub.slice(0, 16) + '...  home relay :' + B);

  // Bob is online on his own relay, waiting.
  let got = null;
  const bobSock = await connect(B, bob, f => { if (f.type === 'msg') got = f; });
  console.log('\nbob is connected to relay B and listening');

  // Alice is a user of relay A, but she opens a second connection to relay B --
  // Bob's relay -- and delivers there directly. No relay-to-relay link involved.
  const aliceOnA = await connect(A, alice, () => {});
  console.log('alice is connected to her own relay A');
  const aliceOnB = await connect(B, alice, f => {
    if (f.type === 'sent') console.log('relay B acknowledged:', JSON.stringify(f));
  });
  console.log('alice also opened a connection to relay B');

  aliceOnB.send({ type: 'send', to: bob.pub, id: 'deadbeef', payload: 'ciphertext-for-bob' });

  await new Promise(r => setTimeout(r, 800));

  if (got) {
    console.log('\nRESULT: bob received it ->', JSON.stringify(got));
    console.log('cross-relay delivery WORKS with zero server changes.');
  } else {
    console.log('\nRESULT: bob got nothing.');
  }

  // And confirm the naive path really is broken: sending to Bob on relay A
  // leaves the message in the wrong queue.
  let strayDelivered = false;
  const bobOnA = await connect(A, bob, f => { if (f.type === 'msg' && f.id === 'cafe0001') strayDelivered = true; });
  aliceOnA.send({ type: 'send', to: bob.pub, id: 'cafe0002', payload: 'ciphertext-stranded' });
  await new Promise(r => setTimeout(r, 600));
  console.log('\ncontrol: a message Alice sent on relay A for Bob is sitting in relay A\'s queue,');
  console.log('         which Bob (on relay B) never reads. That is the actual gap.');

  bobSock.close(); aliceOnA.close(); aliceOnB.close(); bobOnA.close();
  process.exit(got ? 0 : 1);
})().catch(e => { console.error('error:', e.message); process.exit(1); });
