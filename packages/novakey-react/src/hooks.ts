import { NovaKeyStore } from './store.ts';
import type { NovaKeyProviderProps } from './types.ts';

let activeStore: NovaKeyStore | null = null;

/**
 * Reads external store snapshot with React's `useSyncExternalStore` when available,
 * falling back gracefully to direct store snapshots in SSR/headless environments.
 */
function useStoreSnapshot(store: NovaKeyStore) {
  const ReactGlobal = (globalThis as unknown as {
    React?: { useSyncExternalStore?: (sub: unknown, snap: unknown, ssrSnap?: unknown) => ReturnType<typeof store.getSnapshot> };
  }).React;

  if (typeof ReactGlobal?.useSyncExternalStore === 'function') {
    return ReactGlobal.useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);
  }
  return store.getSnapshot();
}

/**
 * Initialize or replace the active NovaKey context store.
 * Can be used as a React Provider component (`<NovaKeyProvider ...>`) or called
 * directly in non-DOM / SSR / test environments.
 */
export function NovaKeyProvider(props: NovaKeyProviderProps): unknown {
  activeStore = new NovaKeyStore(props);
  return props.children ?? activeStore;
}

/**
 * Return the active `NovaKeyStore` instance or throw if `NovaKeyProvider` was not initialized.
 */
export function getActiveNovaKeyStore(): NovaKeyStore {
  if (!activeStore) {
    throw new Error('NovaKey hooks must be used within a <NovaKeyProvider>');
  }
  return activeStore;
}

/**
 * Hook for wallet creation, passkey state, and address resolution.
 */
export function useNovaKey(storeOverride?: NovaKeyStore) {
  const store = storeOverride ?? getActiveNovaKeyStore();
  const snapshot = useStoreSnapshot(store);

  return {
    address: snapshot.address,
    credential: snapshot.credential,
    nonce: snapshot.nonce,
    isCreating: snapshot.isCreating,
    isLocked: snapshot.isLocked,
    isLocking: snapshot.isLocking,
    error: snapshot.error,
    createWallet: store.createWallet,
    lockWallet: store.lockWallet,
    unlockWallet: store.unlockWallet,
    disconnect: store.disconnect,
    subscribe: store.subscribe,
  };
}

/**
 * Hook for signing and submitting gas-sponsored transactions via a NovaKey Relayer.
 */
export function useTransaction(storeOverride?: NovaKeyStore) {
  const store = storeOverride ?? getActiveNovaKeyStore();
  const snapshot = useStoreSnapshot(store);

  return {
    sendSponsoredTx: store.sendSponsoredTx,
    isPending: snapshot.isPending,
    lastReceipt: snapshot.lastReceipt,
    error: snapshot.error,
    subscribe: store.subscribe,
  };
}

/**
 * Hook for configuring social recovery guardians and executing account recovery.
 */
export function useRecovery(storeOverride?: NovaKeyStore) {
  const store = storeOverride ?? getActiveNovaKeyStore();
  const snapshot = useStoreSnapshot(store);

  return {
    guardian: snapshot.guardian,
    isRecovering: snapshot.isRecovering,
    error: snapshot.error,
    setGuardian: store.setGuardian,
    removeGuardian: store.removeGuardian,
    recoverWallet: store.recoverWallet,
    subscribe: store.subscribe,
  };
}

/**
 * Hook for managing emergency security freeze / locking of the smart wallet.
 */
export function useEmergencyLock(storeOverride?: NovaKeyStore) {
  const store = storeOverride ?? getActiveNovaKeyStore();
  const snapshot = useStoreSnapshot(store);

  return {
    isLocked: snapshot.isLocked,
    isLocking: snapshot.isLocking,
    error: snapshot.error,
    lockWallet: store.lockWallet,
    unlockWallet: store.unlockWallet,
    subscribe: store.subscribe,
  };
}
