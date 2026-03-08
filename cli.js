#!/usr/bin/env node
'use strict';

/**
 * zkp-cli — Zero-Knowledge Proof Identity CLI
 *
 * Usage:
 *   node cli.js verifier listen --port 8080
 *   node cli.js prove --verifier 127.0.0.1:8080
 */

const net     = require('net');
const crypto  = require('crypto');
const path    = require('path');

// ─── Load native addon ────────────────────────────────────────────────────────
const native = require('./native/index.node');

// ─── Helpers ──────────────────────────────────────────────────────────────────
function randomNonce() {
  return crypto.randomBytes(32).toString('hex');
}

function log(role, msg) {
  const tag = role === 'verifier' ? '\x1b[36m[Verifier]\x1b[0m' : '\x1b[33m[Prover]\x1b[0m';
  console.log(`${tag} ${msg}`);
}

function sendJSON(socket, obj) {
  socket.write(JSON.stringify(obj) + '\n');
}

// ─── VERIFIER ─────────────────────────────────────────────────────────────────
function startVerifier(port) {
  // Generate PS keypair for verification
  const keypairV = native.psKeygen(5);
  const pkX   = keypairV.pkX;
  const pkYs  = keypairV.pkYs;

  const server = net.createServer((socket) => {
    const challenge = randomNonce();
    log('verifier', `New connection from ${socket.remoteAddress}`);
    log('verifier', `Challenge nonce: \x1b[32m${challenge.slice(0, 16)}...\x1b[0m`);
    log('verifier', 'Waiting for proof...');

    // Step 1: Send challenge + public key to prover
    sendJSON(socket, {
      type:      'challenge',
      challenge,
      pkX,
      pkYs,
    });

    let buffer = '';
    socket.on('data', (data) => {
      buffer += data.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop(); // keep incomplete line

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line);

          if (msg.type === 'proof') {
            log('verifier', 'Proof received. Verifying...');

            // Step 2: Verify the proof
            let result;
            try {
              // verifyNIZKProof expects (proofJson string, challenge, pkX, pkYs)
              // Use the prover's public key sent with the proof
              result = native.verifyNIZKProof(
                JSON.stringify(msg.proof),
                challenge,
                msg.pkX,
                msg.pkYs
              );
            } catch (e) {
              result = { ok: false, errors: [e.message] };
            }

            log('verifier', `verifyNIZKProof result: ${JSON.stringify(result)}`);
            // Result is { resultJson: '{"valid":true,...}' } — parse the inner JSON
            let parsed = result;
            if (result && typeof result.resultJson === 'string') {
              parsed = JSON.parse(result.resultJson);
            } else if (typeof result === 'string') {
              parsed = JSON.parse(result);
            }
            const valid = parsed && parsed.valid === true;

            if (valid) {
              log('verifier', '\x1b[32m✅ VALID — proof accepted\x1b[0m');
              sendJSON(socket, { type: 'result', valid: true });
            } else {
              const errs = result?.errors || ['Verification failed'];
              log('verifier', `\x1b[31m❌ INVALID — ${errs.join(', ')}\x1b[0m`);
              sendJSON(socket, { type: 'result', valid: false, errors: errs });
            }

            socket.end();
          }
        } catch (e) {
          log('verifier', `Parse error: ${e.message}`);
        }
      }
    });

    socket.on('end', () => log('verifier', 'Connection closed.'));
    socket.on('error', (e) => log('verifier', `Socket error: ${e.message}`));
  });

  server.listen(port, () => {
    console.log('\n\x1b[1m╔══════════════════════════════════════╗\x1b[0m');
    console.log(  '\x1b[1m║       ZKP Verifier  Listening        ║\x1b[0m');
    console.log(  '\x1b[1m╚══════════════════════════════════════╝\x1b[0m');
    log('verifier', `Listening on port \x1b[32m${port}\x1b[0m`);
    log('verifier', 'Waiting for prover connection...\n');
  });
}

// ─── PROVER ───────────────────────────────────────────────────────────────────
function startProver(host, port) {
  console.log('\n\x1b[1m╔══════════════════════════════════════╗\x1b[0m');
  console.log(  '\x1b[1m║         ZKP Prover / Wallet          ║\x1b[0m');
  console.log(  '\x1b[1m╚══════════════════════════════════════╝\x1b[0m');
  log('prover', `Connecting to verifier at \x1b[33m${host}:${port}\x1b[0m...\n`);

  const socket = net.connect(port, host, () => {
    log('prover', 'Connected to verifier.');
  });

  // Init wallet
  native.walletInit();

  let buffer = '';
  socket.on('data', (data) => {
    buffer += data.toString();
    const lines = buffer.split('\n');
    buffer = lines.pop();

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);

        if (msg.type === 'challenge') {
          const { challenge, pkX, pkYs } = msg;
          log('prover', `Challenge received: \x1b[33m${challenge.slice(0, 16)}...\x1b[0m`);

          // Generate a credential and proof
          log('prover', 'Generating ZK proof...');

          // Step 1: keygen
          let keypair, sig, sanitised, proofJson, proofId, proof;

          log('prover', 'Step 1: psKeygen...');
          keypair = native.psKeygen(5);
          log('prover', `psKeygen keys: ${JSON.stringify(Object.keys(keypair))}`);
          const skXHex2  = keypair.skX;
          const skYsHex2 = keypair.skYs;
          const pkXHex2  = keypair.pkX;
          const pkYsHex2 = keypair.pkYs;

          // Step 2: sign
          log('prover', 'Step 2: psSign...');
          const attributes = ['Alice', '28', 'India', '900000', 'Kolkata'];
          sig = native.psSign(attributes, skXHex2, skYsHex2);
          log('prover', `psSign keys: ${JSON.stringify(Object.keys(sig))}`);

          // Step 3: store credential — use prover's OWN keypair throughout
          log('prover', 'Step 3: storePSCredential...');
          const rawAttrs = { name: 'Alice', age: '28', country: 'India', income: '900000', city: 'Kolkata' };
          sanitised = {
            attributes:      Object.fromEntries(Object.entries(rawAttrs).map(([k,v]) => [k, String(v)])),
            attribute_order: ['name', 'age', 'country', 'income', 'city'],
            sigma1_hex:      sig.sigma1Hex,
            sigma2_hex:      sig.sigma2Hex,
            pk_x_hex:        pkXHex2,
            pk_ys_hex:       pkYsHex2,
          };
          log('prover', `storePSCredential payload: ${JSON.stringify(sanitised).slice(0,80)}...`);
          native.storePSCredential('self_id', JSON.stringify(sanitised));

          // Step 4: generate proof
          log('prover', 'Step 4: generateNIZKProof...');
          ({ proofJson, proofId } = native.generateNIZKProof(
            'self_id',
            ['country'],
            'verifier',
            challenge
          ));
          log('prover', `proofJson type: ${typeof proofJson}`);
          proof = JSON.parse(proofJson);

          log('prover', 'Proof generated. Sending to verifier...');
          // Send proof + the public key used to sign, so verifier can verify correctly
          sendJSON(socket, { type: 'proof', proof, pkX: pkXHex2, pkYs: pkYsHex2 });
        }

        if (msg.type === 'result') {
          if (msg.valid) {
            log('prover', '\x1b[32m✅ VALID — verifier accepted the proof\x1b[0m');
          } else {
            log('prover', `\x1b[31m❌ INVALID — ${(msg.errors || []).join(', ')}\x1b[0m`);
          }
          socket.end();
          process.exit(0);
        }

      } catch (e) {
        log('prover', `Parse error: ${e.message}`);
      }
    }
  });

  socket.on('error', (e) => {
    log('prover', `\x1b[31mConnection error: ${e.message}\x1b[0m`);
    process.exit(1);
  });

  socket.on('end', () => log('prover', 'Disconnected from verifier.'));
}

// ─── ARG PARSING ──────────────────────────────────────────────────────────────
const args = process.argv.slice(2);

if (args[0] === 'verifier' && args[1] === 'listen') {
  const portIdx = args.indexOf('--port');
  const port = portIdx !== -1 ? parseInt(args[portIdx + 1]) : 8080;
  startVerifier(port);

} else if (args[0] === 'prove') {
  const verifierIdx = args.indexOf('--verifier');
  const addr = verifierIdx !== -1 ? args[verifierIdx + 1] : '127.0.0.1:8080';
  const [host, port] = addr.split(':');
  startProver(host, parseInt(port) || 8080);

} else {
  console.log(`
\x1b[1mzkp-cli\x1b[0m — Zero-Knowledge Proof Identity CLI

\x1b[1mUsage:\x1b[0m
  node cli.js verifier listen --port 8080
  node cli.js prove --verifier 127.0.0.1:8080

\x1b[1mCommands:\x1b[0m
  verifier listen   Start verifier, print challenge, wait for proof
  prove             Connect to verifier, generate and send ZK proof

\x1b[1mOptions:\x1b[0m
  --port <n>        Port for verifier to listen on  (default: 8080)
  --verifier <addr> Verifier address host:port       (default: 127.0.0.1:8080)
  `);
  process.exit(0);
}
