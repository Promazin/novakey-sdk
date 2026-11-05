import {
  createAssertionOptions,
  createRegistrationOptions,
  derToRawSignature,
} from '@novakey/core';
import type {
  AuthenticatorAdapter,
  AuthenticatorAssertionResult,
  CreateWalletParams,
} from './types.ts';

/**
 * Built-in browser WebAuthn adapter utilizing `navigator.credentials.create`
 * and `navigator.credentials.get`.
 */
export class BrowserWebAuthnAdapter implements AuthenticatorAdapter {
  public readonly rpId?: string;

  constructor(options?: { rpId?: string }) {
    this.rpId = options?.rpId;
  }

  /**
   * Register a new passkey credential using `navigator.credentials.create`.
   */
  public async register(params: CreateWalletParams): Promise<{
    rawId: Uint8Array;
    publicKeyBytes: Uint8Array;
    label: string;
  }> {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
      throw new Error('WebAuthn is not supported in this browser environment');
    }

    const options = createRegistrationOptions({
      relyingPartyName: params.relyingPartyName,
      relyingPartyId: this.rpId,
      userName: params.userName,
      userDisplayName: params.userDisplayName,
    });

    const credential = (await navigator.credentials.create({
      publicKey: options,
    })) as PublicKeyCredential | null;

    if (!credential) {
      throw new Error('WebAuthn registration was cancelled or failed');
    }

    const response = credential.response as AuthenticatorAttestationResponse;
    let publicKeyBytes: Uint8Array;

    if (typeof response.getPublicKey === 'function') {
      const spki = response.getPublicKey();
      if (spki) {
        publicKeyBytes = new Uint8Array(spki);
      } else if (response.attestationObject) {
        publicKeyBytes = new Uint8Array(response.attestationObject);
      } else {
        throw new Error('Failed to retrieve public key from WebAuthn response');
      }
    } else if (response.attestationObject) {
      publicKeyBytes = new Uint8Array(response.attestationObject);
    } else {
      throw new Error('Failed to retrieve public key from WebAuthn response');
    }

    return {
      rawId: new Uint8Array(credential.rawId),
      publicKeyBytes,
      label: params.label ?? `${params.userName} Passkey`,
    };
  }

  /**
   * Sign a transaction challenge digest using `navigator.credentials.get`.
   */
  public async sign(
    payloadHash: Uint8Array,
    credentialId: Uint8Array
  ): Promise<AuthenticatorAssertionResult> {
    if (typeof navigator === 'undefined' || !navigator.credentials) {
      throw new Error('WebAuthn is not supported in this browser environment');
    }

    const options = createAssertionOptions({
      challenge: payloadHash,
      allowedCredentialIds: [credentialId],
      relyingPartyId: this.rpId,
    });

    const assertion = (await navigator.credentials.get({
      publicKey: options,
    })) as PublicKeyCredential | null;

    if (!assertion) {
      throw new Error('WebAuthn assertion ceremony was cancelled or failed');
    }

    const resp = assertion.response as AuthenticatorAssertionResponse;
    const derSig = new Uint8Array(resp.signature);
    const compactSig = derToRawSignature(derSig);

    return {
      signature: compactSig,
      authenticatorData: new Uint8Array(resp.authenticatorData),
      clientDataJson: new Uint8Array(resp.clientDataJSON),
    };
  }
}
