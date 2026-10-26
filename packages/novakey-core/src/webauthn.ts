import { derToRawSignature, sha256 } from './crypto.ts';
import type { PasskeyCredential } from './types.ts';

export interface RegistrationOptionsParams {
  relyingPartyName: string;
  relyingPartyId?: string;
  userName: string;
  userDisplayName?: string;
  userId?: Uint8Array;
  challenge?: Uint8Array;
}

export interface AssertionOptionsParams {
  challenge: Uint8Array;
  allowedCredentialIds?: Uint8Array[];
  relyingPartyId?: string;
  userVerification?: 'required' | 'preferred' | 'discouraged';
}

/**
 * Build standard WebAuthn registration options for `navigator.credentials.create()`.
 */
export function createRegistrationOptions(
  params: RegistrationOptionsParams
): PublicKeyCredentialCreationOptions {
  const challenge = params.challenge || crypto.getRandomValues(new Uint8Array(32));
  const userId = params.userId || crypto.getRandomValues(new Uint8Array(16));

  return {
    challenge,
    rp: {
      name: params.relyingPartyName,
      id: params.relyingPartyId,
    },
    user: {
      id: userId,
      name: params.userName,
      displayName: params.userDisplayName || params.userName,
    },
    pubKeyCredParams: [
      {
        alg: -7, // ES256 (NIST P-256 with SHA-256)
        type: 'public-key',
      },
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'required',
    },
    timeout: 60000,
    attestation: 'none',
  };
}

/**
 * Build standard WebAuthn assertion options for `navigator.credentials.get()`.
 */
export function createAssertionOptions(
  params: AssertionOptionsParams
): PublicKeyCredentialRequestOptions {
  const allowCredentials = params.allowedCredentialIds?.map((id) => ({
    type: 'public-key' as const,
    id: id,
    transports: ['internal' as const],
  }));

  return {
    challenge: params.challenge,
    rpId: params.relyingPartyId,
    userVerification: params.userVerification || 'required',
    allowCredentials,
    timeout: 60000,
  };
}

/**
 * Parse an exported WebAuthn registration result to extract 16-byte credential ID
 * and 65-byte uncompressed secp256r1 public key (0x04 || X || Y).
 */
export function parseRegistrationResult(params: {
  rawId: Uint8Array;
  publicKeyBytes: Uint8Array;
  label: string;
}): PasskeyCredential {
  // Ensure credential ID is 16 bytes (derive hash if client authenticator returned longer)
  let credentialId = params.rawId;
  if (credentialId.length !== 16) {
    credentialId = sha256(credentialId).slice(0, 16);
  }

  // Ensure public key is 65-byte uncompressed format (0x04 prefix)
  let publicKey = params.publicKeyBytes;
  if (publicKey.length === 64) {
    const uncompressed = new Uint8Array(65);
    uncompressed[0] = 0x04;
    uncompressed.set(publicKey, 1);
    publicKey = uncompressed;
  } else if (publicKey.length !== 65 || publicKey[0] !== 0x04) {
    throw new Error(
      `Expected 65-byte uncompressed secp256r1 public key, got length ${publicKey.length}`
    );
  }

  return {
    credentialId,
    publicKey,
    label: params.label,
  };
}

/**
 * Parse an assertion result into a compact 64-byte signature.
 */
export function parseAssertionSignature(derSignature: Uint8Array): Uint8Array {
  return derToRawSignature(derSignature);
}
