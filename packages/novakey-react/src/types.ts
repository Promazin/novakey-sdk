import type {
  NovaKeyConfig,
  PasskeyCredential,
} from '../../novakey-core/src/index.ts';

/**
 * Parameters passed to `createWallet`.
 */
export interface CreateWalletParams {
  relyingPartyName: string;
  userName: string;
  userDisplayName?: string;
  label?: string;
}

/**
 * Parameters passed to `sendSponsoredTx`.
 */
export interface SponsoredTxParams {
  to: string;
  amount: string;
  assetContractId: string;
  memo?: string;
  idempotencyKey?: string;
}

/**
 * Receipt returned by `sendSponsoredTx`.
 */
export interface SponsoredTxReceipt {
  txHash: string;
  status: 'SUCCESS' | 'PENDING' | 'FAILED';
  nonce: bigint;
  sponsoredFeeStroops: number;
}

/**
 * Pluggable authenticator adapter so applications and tests can supply
 * browser WebAuthn (`navigator.credentials`), React Native biometrics,
 * or deterministic hardware enclave mocks.
 */
export interface AuthenticatorAdapter {
  register(params: CreateWalletParams): Promise<{
    rawId: Uint8Array;
    publicKeyBytes: Uint8Array;
    label: string;
  }>;
  sign(payloadHash: Uint8Array, credentialId: Uint8Array): Promise<Uint8Array>;
}

/**
 * Snapshot of the NovaKey reactive wallet store.
 */
export interface NovaKeyState {
  address: string | null;
  credential: PasskeyCredential | null;
  guardian: string | null;
  nonce: bigint;
  isCreating: boolean;
  isPending: boolean;
  isRecovering: boolean;
  isLocked: boolean;
  isLocking: boolean;
  lastReceipt: SponsoredTxReceipt | null;
  error: Error | null;
}

/**
 * Props for `NovaKeyProvider`.
 */
export interface NovaKeyProviderProps extends NovaKeyConfig {
  authenticator?: AuthenticatorAdapter;
  children?: unknown;
}
