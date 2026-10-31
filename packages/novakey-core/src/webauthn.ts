import { derToRawSignature, P256_SPKI_HEADER, sha256 } from './crypto.ts';
import type { ParsedAuthenticatorData, PasskeyCredential } from './types.ts';

export { P256_SPKI_HEADER };

/**
 * Maximum UTF-8 byte length for a credential label (matches contract MAX_LABEL_BYTES).
 */
export const MAX_LABEL_BYTES = 64;

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
 * Extract a 65-byte uncompressed secp256r1 public key (`0x04 || X || Y`) from
 * a 91-byte ASN.1 DER `SubjectPublicKeyInfo` (SPKI) buffer returned by
 * `AuthenticatorAttestationResponse.getPublicKey()`.
 */
export function extractPublicKeyFromSpki(spkiBytes: Uint8Array): Uint8Array {
  if (spkiBytes.length !== 91) {
    throw new Error(`Invalid P-256 SPKI length: expected 91 bytes, got ${spkiBytes.length}`);
  }
  for (let i = 0; i < P256_SPKI_HEADER.length; i++) {
    if (spkiBytes[i] !== P256_SPKI_HEADER[i]) {
      throw new Error('Invalid P-256 SPKI header: OID or ASN.1 structure mismatch');
    }
  }
  const publicKey = spkiBytes.slice(26, 91);
  if (publicKey[0] !== 0x04) {
    throw new Error('Invalid P-256 SPKI payload: expected uncompressed point 0x04');
  }
  return publicKey;
}

/**
 * Extract a 65-byte uncompressed secp256r1 public key (`0x04 || X || Y`) from
 * a CBOR-encoded COSE_Key EC2 structure (`kty=2, alg=-7, crv=1, x=-2, y=-3`).
 */
export function extractPublicKeyFromCose(coseBytes: Uint8Array): Uint8Array {
  if (coseBytes.length < 70 || (coseBytes[0] & 0xe0) !== 0xa0) {
    throw new Error('Invalid COSE_Key: expected CBOR map');
  }

  // Locate CBOR negative integer keys -2 (0x21) and -3 (0x22) followed by 32-byte bstr (0x58, 0x20)
  let xBytes: Uint8Array | null = null;
  let yBytes: Uint8Array | null = null;

  for (let i = 1; i <= coseBytes.length - 35; i++) {
    if (coseBytes[i] === 0x21 && coseBytes[i + 1] === 0x58 && coseBytes[i + 2] === 0x20) {
      xBytes = coseBytes.slice(i + 3, i + 35);
      i += 34;
    } else if (coseBytes[i] === 0x22 && coseBytes[i + 1] === 0x58 && coseBytes[i + 2] === 0x20) {
      yBytes = coseBytes.slice(i + 3, i + 35);
      i += 34;
    }
  }

  if (!xBytes || !yBytes) {
    throw new Error('Invalid COSE_Key: missing 32-byte X or Y coordinate');
  }

  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(xBytes, 1);
  uncompressed.set(yBytes, 33);
  return uncompressed;
}

/**
 * Parse a WebAuthn `authenticatorData` byte array into its structured fields:
 * `rpIdHash` (32 bytes), `flags` (1 byte), and `signCount` (4-byte big-endian uint32).
 */
export function parseAuthenticatorData(authData: Uint8Array): ParsedAuthenticatorData {
  if (authData.length < 37) {
    throw new Error(
      `Authenticator data must be at least 37 bytes, got ${authData.length}`
    );
  }

  const rpIdHash = authData.slice(0, 32);
  const rawFlags = authData[32];
  const view = new DataView(authData.buffer, authData.byteOffset + 33, 4);
  const signCount = view.getUint32(0, false);

  return {
    rpIdHash,
    flags: {
      userPresent: Boolean(rawFlags & 0x01),
      userVerified: Boolean(rawFlags & 0x04),
      backupEligible: Boolean(rawFlags & 0x08),
      backupState: Boolean(rawFlags & 0x10),
      attestedCredentialData: Boolean(rawFlags & 0x40),
      extensionDataIncluded: Boolean(rawFlags & 0x80),
      raw: rawFlags,
    },
    signCount,
  };
}

/**
 * Parse an exported WebAuthn registration result to extract 16-byte credential ID
 * and 65-byte uncompressed secp256r1 public key (0x04 || X || Y).
 *
 * Accepts `publicKeyBytes` in any of the following formats:
 * - 65-byte uncompressed SEC1 (`0x04 || X || Y`)
 * - 64-byte raw coordinates (`X || Y`)
 * - 91-byte ASN.1 DER SubjectPublicKeyInfo (`SPKI`)
 * - CBOR-encoded `COSE_Key` EC2 map
 */
export function parseRegistrationResult(params: {
  rawId: Uint8Array;
  publicKeyBytes: Uint8Array;
  label: string;
}): PasskeyCredential {
  const labelBytes = new TextEncoder().encode(params.label);
  if (labelBytes.length > MAX_LABEL_BYTES) {
    throw new Error(
      `Credential label exceeds maximum length of ${MAX_LABEL_BYTES} bytes`
    );
  }

  // Ensure credential ID is 16 bytes (derive hash if client authenticator returned longer)
  let credentialId = params.rawId;
  if (credentialId.length !== 16) {
    credentialId = sha256(credentialId).slice(0, 16);
  }

  // Normalize public key into 65-byte uncompressed format (0x04 prefix)
  let publicKey = params.publicKeyBytes;
  if (publicKey.length === 91) {
    publicKey = extractPublicKeyFromSpki(publicKey);
  } else if (publicKey.length >= 70 && (publicKey[0] & 0xe0) === 0xa0) {
    publicKey = extractPublicKeyFromCose(publicKey);
  } else if (publicKey.length === 64) {
    const uncompressed = new Uint8Array(65);
    uncompressed[0] = 0x04;
    uncompressed.set(publicKey, 1);
    publicKey = uncompressed;
  } else if (publicKey.length !== 65 || publicKey[0] !== 0x04) {
    throw new Error(
      `Expected 65-byte uncompressed secp256r1 public key, got length ${publicKey.length}`
    );
  }

  // Ensure coordinates are not all-zero
  let hasNonZeroCoord = false;
  for (let i = 1; i < 65; i++) {
    if (publicKey[i] !== 0) {
      hasNonZeroCoord = true;
      break;
    }
  }
  if (!hasNonZeroCoord) {
    throw new Error('Invalid secp256r1 public key: coordinates cannot be all zeros');
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
