// Alice talks ONLY to her own relay. Her relay hands the message to Bob's.
'use strict';
const { newIdentity, connect } = require('./client');

const A = 9101, B = 9102;
const B_ADDR = '127.0.0.1:9102';
let pass = 0, fail = 0;
const ok = m => { pass++; console.log('  ok   ' + m); };
const bad = m => { fail++; console.log('  FAIL ' + m); };

(async () => {
  const alice = newIdentity(), bob = newIdentity();

  // --- 1. live delivery across relays -------------------------------------
  let live = null;
  const bobOnB = await connect(B, bob, f => { if (f.type === 'msg') live = f; });
  const aliceOnA = await connect(A, alice, f => {
    if (f.type === 'sent') console.log('     relay A replied:', JSON.stringify(f));
  });
  aliceOnA.send({ type: 'send', to: bob.pub, id: 'aa01', payload: 'live-across-relays', relay: B_ADDR });
  await new Promise(r => setTimeout(r, 900));
  live && live.payload === 'live-across-relays'
    ? ok('live message crossed A -> B while Bob was online')
    : bad('live message did not arrive');
  live && live.from === alice.pub
    ? ok('sender identity preserved across the hop')
    : bad('sender identity lost');

  // --- 2. offline: queued on the RECIPIENT's relay -------------------------
  bobOnB.close();
  await new Promise(r => setTimeout(r, 300));
  aliceOnA.send({ type: 'send', to: bob.pub, id: 'aa02', payload: 'queued-while-offline', relay: B_ADDR });
  await new Promise(r => setTimeout(r, 900));

  let queued = null;
  const bobAgain = await connect(B, bob, f => { if (f.type === 'msg' && f.id === 'aa02') queued = f; });
  await new Promise(r => setTimeout(r, 700));
  queued
    ? ok('message queued on Bob\'s relay and flushed when he reconnected')
    : bad('offline message never arrived');

  // --- 3. no relay hint -> stays local (unchanged behaviour) ---------------
  aliceOnA.send({ type: 'send', to: bob.pub, id: 'aa03', payload: 'no-hint' });
  await new Promise(r => setTimeout(r, 600));
  let strayed = false;
  const probe = await connect(B, bob, f => { if (f.type === 'msg' && f.id === 'aa03') strayed = true; });
  await new Promise(r => setTimeout(r, 500));
  !strayed
    ? ok('without a relay hint the old local-queue behaviour is untouched')
    : bad('unhinted message unexpectedly crossed relays');

  bobAgain.close(); aliceOnA.close(); probe.close();
  console.log(`\npassed ${pass}, failed ${fail}`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('error:', e.message); process.exit(1); });
