#!/usr/bin/env node

import {
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";

const PKCS8_ED25519_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PUBLIC_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MINIMUM_NODE_MAJOR = 22;

function requireSupportedNode() {
  const major = Number.parseInt(process.versions.node.split(".")[0], 10);
  if (!Number.isSafeInteger(major) || major < MINIMUM_NODE_MAJOR) {
    throw new Error(`Node.js ${MINIMUM_NODE_MAJOR} or newer is required`);
  }
}

function decodeHex(label, value, expectedBytes) {
  if (typeof value !== "string" || !/^[0-9a-f]*$/.test(value) || value.length % 2 !== 0) {
    throw new Error(`${label} must be canonical even-length hex`);
  }
  const bytes = Buffer.from(value, "hex");
  if (bytes.toString("hex") !== value) {
    throw new Error(`${label} did not round-trip through hex decoding`);
  }
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    throw new Error(`${label} must be ${expectedBytes} bytes, got ${bytes.length}`);
  }
  return bytes;
}

function privateKeyFromSeed(seed) {
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_SEED_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function rawPublicKey(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  const expectedLength = SPKI_ED25519_PUBLIC_PREFIX.length + 32;
  if (
    der.length !== expectedLength ||
    !der.subarray(0, SPKI_ED25519_PUBLIC_PREFIX.length).equals(SPKI_ED25519_PUBLIC_PREFIX)
  ) {
    throw new Error("Node exported an unexpected Ed25519 SubjectPublicKeyInfo encoding");
  }
  return der.subarray(SPKI_ED25519_PUBLIC_PREFIX.length);
}

function publicKeyFromRaw(publicKey) {
  return createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PUBLIC_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
}

function emit(values) {
  for (const [key, value] of Object.entries(values)) {
    process.stdout.write(`${key}=${value}\n`);
  }
}

function signCommand(seedHex, messageHex) {
  const seed = decodeHex("seed", seedHex, 32);
  const message = decodeHex("message", messageHex);
  const privateKey = privateKeyFromSeed(seed);
  const publicKey = createPublicKey(privateKey);
  const publicKeyBytes = rawPublicKey(publicKey);
  const signature = nodeSign(null, message, privateKey);
  if (signature.length !== 64) {
    throw new Error(`Node returned an unexpected Ed25519 signature length: ${signature.length}`);
  }
  emit({
    node_public_hex: publicKeyBytes.toString("hex"),
    node_signature_hex: signature.toString("hex"),
    node_verifies_node_signature: nodeVerify(null, message, publicKey, signature),
  });
}

function verifyCommand(publicKeyHex, messageHex, signatureHex) {
  const publicKey = publicKeyFromRaw(decodeHex("public key", publicKeyHex, 32));
  const message = decodeHex("message", messageHex);
  const signature = decodeHex("signature", signatureHex, 64);
  emit({
    node_verifies_signature: nodeVerify(null, message, publicKey, signature),
  });
}

function main() {
  requireSupportedNode();
  const [command, ...args] = process.argv.slice(2);
  if (command === "sign" && args.length === 2) {
    signCommand(args[0], args[1]);
    return;
  }
  if (command === "verify" && args.length === 3) {
    verifyCommand(args[0], args[1], args[2]);
    return;
  }
  throw new Error(
    "usage: node tools/node-interop.mjs sign <seed-hex> <message-hex> | verify <public-key-hex> <message-hex> <signature-hex>",
  );
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`node-interop: ${message}\n`);
  process.exitCode = 1;
}
