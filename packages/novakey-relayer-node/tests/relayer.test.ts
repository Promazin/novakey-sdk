import test from 'node:test';
import assert from 'node:assert';
import type { AddressInfo } from 'node:net';
import {
  bytesToHex,
  SECP256R1_HALF_N,
} from '../../novakey-core/src/index.ts';
import {
  createRelayerServer,
  RelayerEngine,
  type RelayRequest,
} from '../src/index.ts';

function createValidRelayRequest(nonce = '0'): RelayRequest {
  const credentialId = new Uint8Array(16).fill(0x01);
  const operationHash = new Uint8Array(32).fill(0xab);
  // Canonical low-s signature: r = 0x02..02, s = 0x03..03
  const signature = new Uint8Array(64);
  signature.fill(0x02, 0, 32);
  signature.fill(0x03, 32, 64);

  return {
    walletAddress: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
    targetContractId: 'CUSDC000000000000000000000000000000000000000000000000000',
    functionName: 'transfer',
    authPayload: {
      credentialIdHex: bytesToHex(credentialId),
      nonce,
      operationHashHex: bytesToHex(operationHash),
      signatureHex: bytesToHex(signature),
    },
    requestedFeeStroops: 5_000,
  };
}

test('RelayerEngine relays valid request and tracks receipt & metrics', async () => {
  const engine = new RelayerEngine();
  const req = createValidRelayRequest('0');

  const receipt = await engine.relay(req);
  assert.strictEqual(receipt.status, 'SUCCESS');
  assert.strictEqual(receipt.txHash.length, 64);
  assert.strictEqual(receipt.sponsoredFeeStroops, 5_000);
  assert.strictEqual(receipt.nonce, '0');

  const stored = engine.getReceipt(receipt.txHash);
  assert.deepStrictEqual(stored, receipt);

  const metrics = engine.getMetrics();
  assert.strictEqual(metrics.totalRelayed, 1);
  assert.strictEqual(metrics.totalRejected, 0);
  assert.strictEqual(metrics.totalFeeSponsoredStroops, 5_000);
});

test('RelayerEngine rejects mempool nonce replay and non-canonical signatures', async () => {
  const engine = new RelayerEngine();
  const req = createValidRelayRequest('1');

  await engine.relay(req);

  // Re-submitting the same nonce for the same wallet is rejected with 409
  await assert.rejects(
    async () => engine.relay(req),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /already relayed/);
      return true;
    }
  );

  // High-s signature is rejected when requireCanonicalLowS is enabled
  const badReq = createValidRelayRequest('2');
  const highSHex = (SECP256R1_HALF_N + 50n).toString(16).padStart(64, '0');
  badReq.authPayload.signatureHex = '02'.repeat(32) + highSHex;

  await assert.rejects(
    async () => engine.relay(badReq),
    /canonical low-s/
  );
});

test('RelayerEngine enforces target contract allowlist and rate limits', async () => {
  const engine = new RelayerEngine({
    allowedTargetContracts: ['CALLOWEDCONTRACT0000000000000000000000000000000000000000'],
    rateLimitPerMinute: 2,
    maxFeeStroops: 10_000,
  });

  // Disallowed contract rejected
  const disallowed = createValidRelayRequest('0');
  await assert.rejects(
    async () => engine.relay(disallowed),
    /not in relayer allowlist/
  );

  // Allowed contract succeeds up to rate limit
  const allowed1 = createValidRelayRequest('0');
  allowed1.targetContractId = 'CALLOWEDCONTRACT0000000000000000000000000000000000000000';
  await engine.relay(allowed1);

  const allowed2 = createValidRelayRequest('1');
  allowed2.targetContractId = 'CALLOWEDCONTRACT0000000000000000000000000000000000000000';
  await engine.relay(allowed2);

  // 3rd request within the minute window triggers 429 rate limit
  const allowed3 = createValidRelayRequest('2');
  allowed3.targetContractId = 'CALLOWEDCONTRACT0000000000000000000000000000000000000000';
  await assert.rejects(
    async () => engine.relay(allowed3),
    /Rate limit exceeded/
  );
});

test('createRelayerServer handles /health, /api/v1/relay, and /api/v1/tx/:hash over HTTP', async () => {
  const engine = new RelayerEngine();
  const server = createRelayerServer(engine);

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Health check
    const healthRes = await fetch(`${baseUrl}/health`);
    assert.strictEqual(healthRes.status, 200);
    const healthJson = (await healthRes.json()) as { status: string };
    assert.strictEqual(healthJson.status, 'ok');

    // 2. Relay a valid transaction
    const relayRes = await fetch(`${baseUrl}/api/v1/relay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(createValidRelayRequest('10')),
    });
    assert.strictEqual(relayRes.status, 200);
    const receipt = (await relayRes.json()) as { txHash: string; status: string };
    assert.strictEqual(receipt.status, 'SUCCESS');

    // 3. Query transaction status by hash
    const txRes = await fetch(`${baseUrl}/api/v1/tx/${receipt.txHash}`);
    assert.strictEqual(txRes.status, 200);
    const queried = (await txRes.json()) as { txHash: string };
    assert.strictEqual(queried.txHash, receipt.txHash);

    // 4. Query non-existent transaction returns 404
    const missingRes = await fetch(`${baseUrl}/api/v1/tx/deadbeef`);
    assert.strictEqual(missingRes.status, 404);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
