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
 * JSON-serializable representation of `AuthPayload` for HTTP transport to a Relayer.
 */
export interface SerializedAuthPayload {
  /** 32-character hex-encoded credential ID (16 bytes) */
  credentialIdHex: string;
  /** Nonce serialized as decimal string */
  nonce: string;
  /** 64-character hex-encoded operation hash (32 bytes) */
  operationHashHex: string;
  /** 128-character hex-encoded compact signature (64 bytes) */
  signatureHex: string;
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

/**
 * Flags decoded from the 33rd byte of WebAuthn `authenticatorData`.
 */
export interface AuthenticatorFlags {
  /** Bit 0 (UP): User Presence result */
  userPresent: boolean;
  /** Bit 2 (UV): User Verification result */
  userVerified: boolean;
  /** Bit 3 (BE): Backup Eligibility */
  backupEligible: boolean;
  /** Bit 4 (BS): Backup State */
  backupState: boolean;
  /** Bit 6 (AT): Attested credential data included */
  attestedCredentialData: boolean;
  /** Bit 7 (ED): Extension data included */
  extensionDataIncluded: boolean;
  /** Raw flag byte */
  raw: number;
}

/**
 * Parsed WebAuthn `authenticatorData` structure (minimum 37 bytes).
 */
export interface ParsedAuthenticatorData {
  /** 32-byte SHA-256 hash of the Relying Party ID */
  rpIdHash: Uint8Array;
  /** Decoded authenticator flags */
  flags: AuthenticatorFlags;
  /** 32-bit big-endian signature counter */
  signCount: number;
}
