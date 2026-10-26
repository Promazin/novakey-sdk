/**
 * NovaKey Core Types
 */

/**
 * A passkey credential registered on a NovaKey smart wallet.
 */
export interface PasskeyCredential {
  /** 16-byte credential ID */
  credentialId: Uint8Array;
  /** 65-byte uncompressed secp256r1 public key (0x04 || X || Y) */
  publicKey: Uint8Array;
  /** Human-readable label for device identification */
  label: string;
}

/**
 * Payload that the passkey device signs.
 * Mirrors `SignaturePayload` in the Soroban contract.
 */
export interface SignaturePayload {
  /** Monotonic nonce preventing replay attacks */
  nonce: bigint;
  /** 32-byte operation hash representing the transaction context */
  operationHash: Uint8Array;
}

/**
 * Full authorization payload forwarded to relayer and Soroban `__check_auth`.
 * Layout mirrors `AuthPayload` in the Soroban contract.
 */
export interface AuthPayload {
  /** 16-byte credential ID */
  credentialId: Uint8Array;
  /** Signed payload containing nonce and operation hash */
  signed: SignaturePayload;
  /** 64-byte compact signature (r || s), low-s normalized */
  signature: Uint8Array;
}

/**
 * Configuration for wallet creation and deployment.
 */
export interface WalletDeploymentConfig {
  /** Stellar address of the owner */
  owner: string;
  /** 16-byte credential ID */
  credentialId: Uint8Array;
  /** 65-byte uncompressed secp256r1 public key */
  publicKey: Uint8Array;
  /** Human-readable label */
  label: string;
}

/**
 * Supported Stellar network environments.
 */
export type StellarNetwork = 'testnet' | 'mainnet' | 'futurenet' | 'standalone';

/**
 * NovaKey SDK configuration options.
 */
export interface NovaKeyConfig {
  network: StellarNetwork;
  rpcUrl: string;
  factoryContractId?: string;
  relayerUrl?: string;
}
