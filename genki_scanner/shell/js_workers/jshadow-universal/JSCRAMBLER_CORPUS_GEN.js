#!/usr/bin/env node
/**
 * J-Shadow — JScrambler real-corpus generator (RUN LOCALLY).
 * The sandbox where J-Shadow was built has a clock that doesn't match
 * JScrambler's servers, so its HMAC signatures get 401'd. On your own machine
 * the clock is real → this works. Generates a JScrambler VARIANT MATRIX so we
 * can calibrate the detector against real JScrambler (true positives).
 *
 *   npm install jscrambler
 *   JSCRAMBLER_ACCESS_KEY=xxx JSCRAMBLER_SECRET_KEY=yyy node JSCRAMBLER_CORPUS_GEN.js
 *   → produces ./jscr_corpus/<variant>/app.js  → zip it and send back.
 */
const jscrambler = require('jscrambler').default;
const fs = require('fs');
const path = require('path');

const KEYS = {
  accessKey: process.env.JSCRAMBLER_ACCESS_KEY || 'PUT_ACCESS_KEY_HERE',
  secretKey: process.env.JSCRAMBLER_SECRET_KEY || 'PUT_SECRET_KEY_HERE'
};
const BASE = { keys: KEYS, host: 'api4.jscrambler.com', port: 443, jscramblerVersion: '8.6' };

const SRC = `
function processPayment(cardNumber, amount, userType) {
  var rates = { premium: 0.02, standard: 0.03, guest: 0.05 };
  var apiKey = "sk_live_4242SECRET";
  if (userType === "premium") { console.log("VIP to " + apiKey); }
  var fee = amount * (rates[userType] || 0.05);
  return { charged: amount + fee, token: btoa(cardNumber + ":" + apiKey) };
}
module.exports = { processPayment };
`;

// variant matrix — each isolates a JScrambler capability (uses trial protections)
const VARIANTS = {
  basic:       [{ name: 'objectPropertiesSparsing' }, { name: 'variableMasking' }, { name: 'stringConcealing' }],
  advanced:    [{ name: 'variableMasking' }, { name: 'stringConcealing' }, { name: 'controlFlowFlattening' }, { name: 'functionOutlining' }, { name: 'deadCodeInjection' }],
  selfdefend:  [{ name: 'variableMasking' }, { name: 'stringConcealing' }, { name: 'selfDefending' }, { name: 'controlFlowFlattening' }],
  domainlock:  [{ name: 'variableMasking' }, { name: 'stringConcealing' }], // + set domainLock in app config below
  vm_heavy:    [{ name: 'variableMasking' }, { name: 'stringConcealing' }, { name: 'controlFlowFlattening', options: { flattenControlFlow: true } }, { name: 'functionReordering' }, { name: 'propertyKeysObfuscation' }]
};

(async () => {
  fs.mkdirSync('./jscr_src', { recursive: true });
  fs.writeFileSync('./jscr_src/app.js', SRC);
  const client = new jscrambler.Client(BASE);
  // sanity: check auth first
  try { await jscrambler.getApplications(client); console.log('✅ auth OK'); }
  catch (e) { console.log('❌ auth failed:', e.message); console.log('   → check keys + system clock (HMAC is time-based).'); return; }

  for (const [name, params] of Object.entries(VARIANTS)) {
    try {
      const cfg = { ...BASE, filesSrc: ['./jscr_src/app.js'], filesDest: `./jscr_corpus/${name}/`, params };
      if (name === 'domainlock') cfg.applicationTypes = { desktop: true }, cfg.domainLock = ['example.com'];
      await jscrambler.protectAndDownload(cfg);
      console.log('✅ ' + name);
    } catch (e) { console.log('❌ ' + name + ':', (e.message || String(e)).slice(0, 160)); }
  }
  console.log('\nDone → zip ./jscr_corpus/ and send it back to calibrate the detector.');
})();
