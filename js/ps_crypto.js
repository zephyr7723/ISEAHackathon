'use strict';
const native = require('../native/index.node');

function psKeyGen(numAttributes) {
  return native.psKeygen(numAttributes);
}

function psSign(sk, attributes) {
  return native.psSign(sk, attributes);
}

function psReRandomize(signature) {
  // Re-randomization may not be directly exposed; return as-is if not available
  return signature;
}

function pedersenCommit(value, blinding) {
  return native.getAttributeCommitments(value, blinding);
}

function nizkProveCommitment(params) {
  return native.generateNIZKProof(params);
}

function nizkVerifyCommitment(params) {
  return native.verifyNIZKProof(params);
}

function nizkProvePSSignature(params) {
  return native.generateNIZKProof(params);
}

function nizkVerifyPSSignature(params) {
  return native.verifyNIZKProof(params);
}

function attributeToScalar(attr) {
  // Convert attribute string/number to a scalar representation
  return Buffer.from(JSON.stringify(attr)).toString('hex');
}

function randomScalar() {
  return require('crypto').randomBytes(32).toString('hex');
}

module.exports = {
  psKeyGen,
  psSign,
  psReRandomize,
  pedersenCommit,
  nizkProveCommitment,
  nizkVerifyCommitment,
  nizkProvePSSignature,
  nizkVerifyPSSignature,
  attributeToScalar,
  randomScalar,
};
