import test from 'node:test';
import assert from 'node:assert';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  derToRawSignature,
  deriveCredentialSalt,
  hashPayload,
  hexToBytes,
  isLowSSignature,
  rawToDerSignature,
  SECP256R1_HALF_N,
  SECP256R1_N,
} from '../src/crypto.ts';

test('derToRawSignature converts valid DER to 64 bytes', () => {
  // ASN.1 DER with 32-byte r and 32-byte s
  const rHex = '1122334455667788990011223344556677889900112233445566778899001122';
  const sHex = '0102030405060708090001020304050607080900010203040506070809000102';

  const r = hexToBytes(rHex);
  const s = hexToBytes(sHex);

  const der = new Uint8Array([
    0x30, 0x44, // sequence, 68 bytes
    0x02, 0x20, ...r, // integer r (32 bytes)
    0x02, 0x20, ...s, // integer s (32 bytes)
  ]);

  const raw = derToRawSignature(der);
  assert.strictEqual(raw.length, 64);
  assert.strictEqual(bytesToHex(raw.slice(0, 32)), rHex);
  assert.strictEqual(bytesToHex(raw.slice(32, 64)), sHex);
});

test('derToRawSignature normalizes high-s to low-s', () => {
  const rHex = '1122334455667788990011223344556677889900112233445566778899001122';
  // s chosen so that s > half_order
  const highS = SECP256R1_HALF_N + 100n;
  const expectedLowS = SECP256R1_N - highS;

  const r = hexToBytes(rHex);
  const sBytes = hexToBytes(highS.toString(16).padStart(64, '0'));

  // If high bit of s is set, DER prepends 0x00
  const der = new Uint8Array([
    0x30, 0x45,
    0x02, 0x20, ...r,
    0x02, 0x21, 0x00, ...sBytes,
  ]);

  const raw = derToRawSignature(der);
  const resultSHex = bytesToHex(raw.slice(32, 64));
  const expectedSHex = expectedLowS.toString(16).padStart(64, '0');

  assert.strictEqual(resultSHex, expectedSHex);
});

test('rawToDerSignature roundtrips with derToRawSignature', () => {
  const rawHex =
    '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20' +
    '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';
  const raw = hexToBytes(rawHex);

  const der = rawToDerSignature(raw);
  const parsedRaw = derToRawSignature(der);

  assert.deepStrictEqual(parsedRaw, raw);
});

test('hashPayload correctly packages little-endian nonce and operation hash', () => {
  const nonce = 1n; // le: [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  const opHash = new Uint8Array(32);
  opHash.fill(0xab);

  const hash = hashPayload(nonce, opHash);
  assert.strictEqual(hash.length, 32);

  // Re-hashing the same nonce and opHash is deterministic
  const hash2 = hashPayload(nonce, opHash);
  assert.deepStrictEqual(hash, hash2);

  // Different nonce produces different hash
  const hashDifferentNonce = hashPayload(2n, opHash);
  assert.notDeepStrictEqual(hash, hashDifferentNonce);
});

test('deriveCredentialSalt produces 32-byte hash', () => {
  const credId = new Uint8Array(16);
  credId[0] = 0x42;

  const salt = deriveCredentialSalt(credId);
  assert.strictEqual(salt.length, 32);

  const salt2 = deriveCredentialSalt(credId);
  assert.deepStrictEqual(salt, salt2);
});

test('hexToBytes and bytesToHex roundtrip', () => {
  const hex = '0123456789abcdef';
  const bytes = hexToBytes(hex);
  assert.strictEqual(bytesToHex(bytes), hex);
});

test('derToRawSignature rejects malformed DER and zero scalars', () => {
  // Too short
  assert.throws(() => derToRawSignature(new Uint8Array([0x30, 0x02])), /buffer too short/);

  // Zero r scalar
  const zeroR = new Uint8Array(32);
  const validS = new Uint8Array(32).fill(0x01);
  const derZeroR = new Uint8Array([
    0x30, 0x44,
    0x02, 0x20, ...zeroR,
    0x02, 0x20, ...validS,
  ]);
  assert.throws(() => derToRawSignature(derZeroR), /r out of curve order bounds/);

  // Trailing bytes after sequence
  const derTrailing = new Uint8Array([
    0x30, 0x44,
    0x02, 0x20, ...validS,
    0x02, 0x20, ...validS,
    0xff,
  ]);
  assert.throws(() => derToRawSignature(derTrailing), /sequence length mismatch/);
});

test('isLowSSignature validates canonical low-s compact signatures', () => {
  const validLowS = new Uint8Array(64).fill(0x01);
  assert.strictEqual(isLowSSignature(validLowS), true);

  // Zero signature is invalid
  assert.strictEqual(isLowSSignature(new Uint8Array(64)), false);

  // High-s signature is non-canonical
  const highS = SECP256R1_HALF_N + 1n;
  const highSSig = new Uint8Array(64);
  highSSig.fill(0x01, 0, 32);
  highSSig.set(hexToBytes(highS.toString(16).padStart(64, '0')), 32);
  assert.strictEqual(isLowSSignature(highSSig), false);
});

test('bytesToBase64Url and base64UrlToBytes roundtrip', () => {
  const input = new Uint8Array([0xfb, 0xff, 0xfe, 0x00, 0x10, 0x20, 0x30]);
  const encoded = bytesToBase64Url(input);
  assert.ok(!encoded.includes('+'));
  assert.ok(!encoded.includes('/'));
  assert.ok(!encoded.includes('='));

  const decoded = base64UrlToBytes(encoded);
  assert.deepStrictEqual(decoded, input);
});
