import test from 'node:test';
import assert from 'node:assert';
import type { AddressInfo } from 'node:net';
import {
  createRelayerServer,
  RelayerEngine,
} from '../../novakey-relayer-node/src/index.ts';
import {
  NovaKeyProvider,
  useEmergencyLock,
  useNovaKey,
  useRecovery,
  useTransaction,
  type AuthenticatorAdapter,
} from '../src/index.ts';

function createMockAuthenticator(): AuthenticatorAdapter {
  const rawId = new Uint8Array(16).fill(0x07);
  const publicKeyBytes = new Uint8Array(65);
  publicKeyBytes[0] = 0x04;
  publicKeyBytes.fill(0x42, 1);

  return {
    async register(params) {
      return {
        rawId,
        publicKeyBytes,
        label: params.label ?? `${params.relyingPartyName} Device`,
      };
    },
    async sign(_payloadHash) {
      // Return valid canonical low-s 64-byte compact signature
      const sig = new Uint8Array(64);
      sig.fill(0x02, 0, 32);
      sig.fill(0x03, 32, 64);
      return sig;
    },
  };
}

test('NovaKeyProvider and useNovaKey create wallet deterministically and notify subscribers', async () => {
  NovaKeyProvider({
    network: 'testnet',
    rpcUrl: 'https://soroban-testnet.stellar.org',
    authenticator: createMockAuthenticator(),
  });

  let notifications = 0;
  const { createWallet, subscribe } = useNovaKey();
  const unsubscribe = subscribe(() => {
    notifications += 1;
  });

  const address = await createWallet({
    relyingPartyName: 'NovaKey Cash',
    userName: 'maria@example.com',
  });

  assert.ok(address.startsWith('C'));
  assert.strictEqual(address.length, 56);
  assert.ok(notifications >= 2);

  const afterState = useNovaKey();
  assert.strictEqual(afterState.address, address);
  assert.strictEqual(afterState.nonce, 0n);
  assert.strictEqual(afterState.isCreating, false);

  unsubscribe();
});

test('useTransaction signs and submits sponsored transactions through @novakey/relayer-node', async () => {
  const engine = new RelayerEngine();
  const server = createRelayerServer(engine);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;

  try {
    NovaKeyProvider({
      network: 'testnet',
      rpcUrl: 'https://soroban-testnet.stellar.org',
      relayerUrl: `http://127.0.0.1:${port}/api/v1/relay`,
      authenticator: createMockAuthenticator(),
    });

    const { createWallet } = useNovaKey();
    await createWallet({
      relyingPartyName: 'NovaKey Cash',
      userName: 'carlos@example.com',
    });

    const { sendSponsoredTx } = useTransaction();
    const receipt = await sendSponsoredTx({
      to: 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      amount: '50.00',
      assetContractId: 'CUSDC000000000000000000000000000000000000000000000000000',
    });

    assert.strictEqual(receipt.status, 'SUCCESS');
    assert.strictEqual(receipt.txHash.length, 64);
    assert.strictEqual(receipt.nonce, 0n);

    // Nonce advances to 1n after sponsored tx
    assert.strictEqual(useNovaKey().nonce, 1n);
    assert.strictEqual(engine.getMetrics().totalRelayed, 1);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('useRecovery manages guardian configuration and executes credential recovery', async () => {
  NovaKeyProvider({
    network: 'testnet',
    rpcUrl: 'https://soroban-testnet.stellar.org',
    authenticator: createMockAuthenticator(),
  });

  await useNovaKey().createWallet({
    relyingPartyName: 'NovaKey Recovery Demo',
    userName: 'amina@example.com',
  });

  const recovery = useRecovery();

  // Recovery without guardian fails
  const newPk = new Uint8Array(65);
  newPk[0] = 0x04;
  newPk.fill(0x88, 1);

  await assert.rejects(
    async () =>
      recovery.recoverWallet({
        newRawId: new Uint8Array(16).fill(0x09),
        newPublicKeyBytes: newPk,
        newLabel: 'Recovered iPhone',
      }),
    /GuardianNotSet/
  );

  // Set guardian and recover
  const guardianAddr = 'GGUARDIAN00000000000000000000000000000000000000000000000';
  await recovery.setGuardian(guardianAddr);
  assert.strictEqual(useRecovery().guardian, guardianAddr);

  await recovery.recoverWallet({
    newRawId: new Uint8Array(16).fill(0x09),
    newPublicKeyBytes: newPk,
    newLabel: 'Recovered iPhone',
  });

  const updated = useNovaKey();
  assert.strictEqual(updated.credential?.label, 'Recovered iPhone');
  assert.strictEqual(updated.nonce, 1n);
});

test('useEmergencyLock manages freeze state and recovers seamlessly', async () => {
  NovaKeyProvider({
    network: 'testnet',
    rpcUrl: 'https://soroban-testnet.stellar.org',
    authenticator: createMockAuthenticator(),
  });

  await useNovaKey().createWallet({
    relyingPartyName: 'NovaKey Emergency Freeze',
    userName: 'security@example.com',
  });

  const { isLocked, lockWallet, unlockWallet } = useEmergencyLock();
  assert.strictEqual(isLocked, false);

  // Lock wallet
  await lockWallet();
  assert.strictEqual(useEmergencyLock().isLocked, true);
  assert.strictEqual(useNovaKey().isLocked, true);

  // Unlock wallet
  await unlockWallet();
  assert.strictEqual(useEmergencyLock().isLocked, false);

  // Re-lock and verify recovery resets lock
  await lockWallet();
  assert.strictEqual(useEmergencyLock().isLocked, true);

  const recovery = useRecovery();
  await recovery.setGuardian('GGUARDIAN00000000000000000000000000000000000000000000000');

  const newPk = new Uint8Array(65);
  newPk[0] = 0x04;
  newPk.fill(0x99, 1);
  await recovery.recoverWallet({
    newRawId: new Uint8Array(16).fill(0x33),
    newPublicKeyBytes: newPk,
    newLabel: 'New Secure Device',
  });

  // Automatically unlocked upon guardian recovery
  assert.strictEqual(useEmergencyLock().isLocked, false);
});
