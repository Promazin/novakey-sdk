import {
  bytesToHex,
  deriveCredentialSalt,
  hashPayload,
} from './crypto.ts';
import type {
  AuthPayload,
  NovaKeyConfig,
  PasskeyCredential,
  SignaturePayload,
} from './types.ts';

/**
 * Main client for interacting with NovaKey smart wallets and factories.
 */
export class NovaKeyWalletClient {
  public readonly config: NovaKeyConfig;

  constructor(config: NovaKeyConfig) {
    this.config = config;
  }

  /**
   * Derive the 32-byte salt used for deterministic wallet deployment.
   * Matches `FactoryContract::derive_salt`.
   */
  public deriveSalt(credentialId: Uint8Array): Uint8Array {
    return deriveCredentialSalt(credentialId);
  }

  /**
   * Compute the hash that the passkey device must sign for a given operation.
   * Layout: `SHA-256(nonce_le_8_bytes || operation_hash_32_bytes)`
   */
  public hashOperationPayload(nonce: bigint, operationHash: Uint8Array): Uint8Array {
    return hashPayload(nonce, operationHash);
  }

  /**
   * Assemble the structured `AuthPayload` passed to Soroban's `__check_auth`.
   */
  public buildAuthPayload(params: {
    credentialId: Uint8Array;
    nonce: bigint;
    operationHash: Uint8Array;
    signature: Uint8Array;
  }): AuthPayload {
    if (params.credentialId.length !== 16) {
      throw new Error('Credential ID must be exactly 16 bytes');
    }
    if (params.operationHash.length !== 32) {
      throw new Error('Operation hash must be exactly 32 bytes');
    }
    if (params.signature.length !== 64) {
      throw new Error('Compact signature must be exactly 64 bytes');
    }

    const signed: SignaturePayload = {
      nonce: params.nonce,
      operationHash: params.operationHash,
    };

    return {
      credentialId: params.credentialId,
      signed,
      signature: params.signature,
    };
  }

  /**
   * Format a credential for Soroban contract invocation.
   */
  public formatCredentialArgs(credential: PasskeyCredential): {
    credentialIdHex: string;
    publicKeyHex: string;
    label: string;
  } {
    return {
      credentialIdHex: bytesToHex(credential.credentialId),
      publicKeyHex: bytesToHex(credential.publicKey),
      label: credential.label,
    };
  }
}
