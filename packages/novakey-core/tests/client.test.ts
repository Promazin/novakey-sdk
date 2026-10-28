import test from 'node:test';
import assert from 'node:assert';
import { NovaKeyWalletClient } from '../src/client.ts';
import {
  createAssertionOptions,
  createRegistrationOptions,
  extractPublicKeyFromCose,
  extractPublicKeyFromSpki,
  P256_SPKI_HEADER,
  parseAuthenticatorData,
  parseRegistrationResult,
} from '../src/webauthn.ts';

test('NovaKeyWalletClient initializes and formats credentials', () => {
  const client = new NovaKeyWalletClient({
    network: 'testnet',
    rpcUrl: 'https://soroban-testnet.stellar.org',
    factoryContractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
  });

  const credentialId = new Uint8Array(16);
  credentialId[0] = 0x01;
  const publicKey = new Uint8Array(65);
  publicKey[0] = 0x04;
  publicKey[1] = 0x02;

  const formatted = client.formatCredentialArgs({
    credentialId,
    publicKey,
    label: 'MacBook TouchID',
  });

  assert.strictEqual(formatted.credentialIdHex, '01000000000000000000000000000000');
  assert.strictEqual(formatted.label, 'MacBook TouchID');
});

test('NovaKeyWalletClient buildAuthPayload verifies parameter lengths', () => {
  const client = new NovaKeyWalletClient({
    network: 'testnet',
    rpcUrl: 'https://soroban-testnet.stellar.org',
  });

  const credentialId = new Uint8Array(16);
  const nonce = 0n;
  const operationHash = new Uint8Array(32);
  const signature = new Uint8Array(64);

  const payload = client.buildAuthPayload({
    credentialId,
    nonce,
    operationHash,
    signature,
  });

  assert.deepStrictEqual(payload.credentialId, credentialId);
  assert.strictEqual(payload.signed.nonce, 0n);
  assert.deepStrictEqual(payload.signed.operationHash, operationHash);
  assert.deepStrictEqual(payload.signature, signature);

  // Rejects invalid credentialId length
  assert.throws(
    () =>
      client.buildAuthPayload({
        credentialId: new Uint8Array(10),
        nonce,
        operationHash,
        signature,
      }),
    /Credential ID must be exactly 16 bytes/
  );

  // Rejects invalid operationHash length
  assert.throws(
    () =>
      client.buildAuthPayload({
        credentialId,
        nonce,
        operationHash: new Uint8Array(20),
        signature,
      }),
    /Operation hash must be exactly 32 bytes/
  );

  // Rejects invalid signature length
  assert.throws(
    () =>
      client.buildAuthPayload({
        credentialId,
        nonce,
        operationHash,
        signature: new Uint8Array(32),
      }),
    /Compact signature must be exactly 64 bytes/
  );
});

test('WebAuthn registration and assertion options builders', () => {
  const regOpts = createRegistrationOptions({
    relyingPartyName: 'NovaKey Demo',
    userName: 'alice@example.com',
  });

  assert.strictEqual(regOpts.rp.name, 'NovaKey Demo');
  assert.strictEqual(regOpts.user.name, 'alice@example.com');
  assert.strictEqual(regOpts.pubKeyCredParams[0].alg, -7);

  const challenge = new Uint8Array(32);
  const assertOpts = createAssertionOptions({
    challenge,
  });

  assert.deepStrictEqual(assertOpts.challenge, challenge);
  assert.strictEqual(assertOpts.userVerification, 'required');
});

test('parseRegistrationResult validates uncompressed secp256r1 keys', () => {
  const rawId = new Uint8Array(16);
  rawId.fill(0x05);

  const pk65 = new Uint8Array(65);
  pk65[0] = 0x04;
  pk65.fill(0xaa, 1);

  const cred = parseRegistrationResult({
    rawId,
    publicKeyBytes: pk65,
    label: 'Pixel 9',
  });

  assert.strictEqual(cred.publicKey.length, 65);
  assert.strictEqual(cred.publicKey[0], 0x04);
  assert.strictEqual(cred.label, 'Pixel 9');

  // Rejects invalid prefix
  const badPk = new Uint8Array(65);
  badPk[0] = 0x02; // compressed
  assert.throws(
    () =>
      parseRegistrationResult({
        rawId,
        publicKeyBytes: badPk,
        label: 'Bad',
      }),
    /Expected 65-byte uncompressed secp256r1 public key/
  );

  // Rejects all-zero coordinates
  const zeroCoordPk = new Uint8Array(65);
  zeroCoordPk[0] = 0x04;
  assert.throws(
    () =>
      parseRegistrationResult({
        rawId,
        publicKeyBytes: zeroCoordPk,
        label: 'Zero Key',
      }),
    /coordinates cannot be all zeros/
  );

  // Rejects label > 64 bytes
  assert.throws(
    () =>
      parseRegistrationResult({
        rawId,
        publicKeyBytes: pk65,
        label: 'x'.repeat(65),
      }),
    /Credential label exceeds maximum length/
  );
});

test('extractPublicKeyFromSpki and extractPublicKeyFromCose parse standard WebAuthn keys', () => {
  const x = new Uint8Array(32).fill(0x11);
  const y = new Uint8Array(32).fill(0x22);

  // Construct 91-byte SPKI
  const spki = new Uint8Array(91);
  spki.set(P256_SPKI_HEADER, 0);
  spki[26] = 0x04;
  spki.set(x, 27);
  spki.set(y, 59);

  const fromSpki = extractPublicKeyFromSpki(spki);
  assert.strictEqual(fromSpki.length, 65);
  assert.strictEqual(fromSpki[0], 0x04);
  assert.deepStrictEqual(fromSpki.slice(1, 33), x);
  assert.deepStrictEqual(fromSpki.slice(33, 65), y);

  // Construct CBOR COSE_Key (map of 5 pairs: kty=2, alg=-7, crv=1, x=-2, y=-3)
  const cose = new Uint8Array([
    0xa5, // map(5)
    0x01, 0x02, // 1: 2 (EC2)
    0x03, 0x26, // 3: -7 (ES256)
    0x20, 0x01, // -1: 1 (P-256)
    0x21, 0x58, 0x20, ...x, // -2: bstr(32) X
    0x22, 0x58, 0x20, ...y, // -3: bstr(32) Y
  ]);

  const fromCose = extractPublicKeyFromCose(cose);
  assert.deepStrictEqual(fromCose, fromSpki);

  // parseRegistrationResult auto-detects both SPKI and COSE
  const credSpki = parseRegistrationResult({
    rawId: new Uint8Array(16).fill(0x01),
    publicKeyBytes: spki,
    label: 'SPKI Key',
  });
  assert.deepStrictEqual(credSpki.publicKey, fromSpki);

  const credCose = parseRegistrationResult({
    rawId: new Uint8Array(16).fill(0x02),
    publicKeyBytes: cose,
    label: 'COSE Key',
  });
  assert.deepStrictEqual(credCose.publicKey, fromCose);
});

test('parseAuthenticatorData extracts rpIdHash, flags, and signCount', () => {
  const authData = new Uint8Array(37);
  authData.fill(0xaa, 0, 32); // rpIdHash
  authData[32] = 0x01 | 0x04; // UP + UV
  const view = new DataView(authData.buffer);
  view.setUint32(33, 42, false); // signCount = 42

  const parsed = parseAuthenticatorData(authData);
  assert.strictEqual(parsed.rpIdHash.length, 32);
  assert.strictEqual(parsed.flags.userPresent, true);
  assert.strictEqual(parsed.flags.userVerified, true);
  assert.strictEqual(parsed.flags.attestedCredentialData, false);
  assert.strictEqual(parsed.signCount, 42);
});

test('NovaKeyWalletClient serializeAuthPayload and deserializeAuthPayload roundtrip', () => {
  const client = new NovaKeyWalletClient({
    network: 'testnet',
    rpcUrl: 'https://soroban-testnet.stellar.org',
  });

  const payload = client.buildAuthPayload({
    credentialId: new Uint8Array(16).fill(0x09),
    nonce: 15n,
    operationHash: new Uint8Array(32).fill(0xab),
    signature: new Uint8Array(64).fill(0xcd),
  });

  const serialized = client.serializeAuthPayload(payload);
  assert.strictEqual(serialized.nonce, '15');

  const restored = client.deserializeAuthPayload(serialized);
  assert.deepStrictEqual(restored, payload);
});
