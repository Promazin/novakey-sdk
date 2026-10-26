import test from 'node:test';
import assert from 'node:assert';
import { NovaKeyWalletClient } from '../src/client.ts';
import {
  createAssertionOptions,
  createRegistrationOptions,
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
});
