import {
  bytesToHex,
  deriveCredentialSalt,
  hashPayload,
  hexToBytes,
  predictContractAddress,
  sha256,
  verifySecp256r1Digest,
} from './crypto.ts';
import type {
  AuthPayload,
  NovaKeyConfig,
  OperationPayloadResult,
  PasskeyCredential,
  SerializedAuthPayload,
  SerializedPasskeyCredential,
  SignaturePayload,
  TransferOperationParams,
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

  /**
   * Serialize an `AuthPayload` into a JSON-safe transport object for relayer submission.
   */
  public serializeAuthPayload(payload: AuthPayload): SerializedAuthPayload {
    return {
      credentialIdHex: bytesToHex(payload.credentialId),
      nonce: payload.signed.nonce.toString(10),
      operationHashHex: bytesToHex(payload.signed.operationHash),
      signatureHex: bytesToHex(payload.signature),
    };
  }

  /**
   * Deserialize a JSON transport object back into a typed `AuthPayload`.
   */
  public deserializeAuthPayload(serialized: SerializedAuthPayload): AuthPayload {
    return this.buildAuthPayload({
      credentialId: hexToBytes(serialized.credentialIdHex),
      nonce: BigInt(serialized.nonce),
      operationHash: hexToBytes(serialized.operationHashHex),
      signature: hexToBytes(serialized.signatureHex),
    });
  }

  /**
   * Predict the deterministic smart wallet contract address for a given credential.
   */
  public predictWalletAddress(
    credentialId: Uint8Array,
    factoryContractId?: string
  ): string {
    const factory = factoryContractId ?? this.config.factoryContractId;
    if (!factory) {
      throw new Error(
        'Factory contract ID must be configured or passed to predictWalletAddress'
      );
    }
    const salt = this.deriveSalt(credentialId);
    return predictContractAddress(factory, salt);
  }

  /**
   * Build the operation preimage and 32-byte SHA-256 operation hash for a standard transfer.
   */
  public buildTransferOperation(params: TransferOperationParams): OperationPayloadResult {
    const memo = params.memo ?? '';
    const preimage = new TextEncoder().encode(
      `${params.walletAddress}:${params.assetContractId}:${params.to}:${params.amount}:${memo}`
    );
    const operationHash = sha256(preimage);
    return { preimage, operationHash };
  }

  /**
   * Verify an `AuthPayload` against a 65-byte uncompressed public key.
   */
  public verifyAuthPayload(payload: AuthPayload, publicKey: Uint8Array): boolean {
    const payloadHash = this.hashOperationPayload(
      payload.signed.nonce,
      payload.signed.operationHash
    );
    return verifySecp256r1Digest(publicKey, payloadHash, payload.signature);
  }

  /**
   * Serialize a `PasskeyCredential` into a JSON transport representation.
   */
  public serializeCredential(credential: PasskeyCredential): SerializedPasskeyCredential {
    return {
      credentialIdHex: bytesToHex(credential.credentialId),
      publicKeyHex: bytesToHex(credential.publicKey),
      label: credential.label,
    };
  }

  /**
   * Deserialize a `SerializedPasskeyCredential` back into typed byte buffers.
   */
  public deserializeCredential(
    serialized: SerializedPasskeyCredential
  ): PasskeyCredential {
    return {
      credentialId: hexToBytes(serialized.credentialIdHex),
      publicKey: hexToBytes(serialized.publicKeyHex),
      label: serialized.label,
    };
  }
}
