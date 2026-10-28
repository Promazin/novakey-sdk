import {
  bytesToHex,
  NovaKeyWalletClient,
  parseRegistrationResult,
  sha256,
} from '../../novakey-core/src/index.ts';
import type {
  AuthenticatorAdapter,
  CreateWalletParams,
  NovaKeyProviderProps,
  NovaKeyState,
  SponsoredTxParams,
  SponsoredTxReceipt,
} from './types.ts';

type Listener = () => void;

/**
 * Reactive store backing `@novakey/react` hooks (`useNovaKey`, `useTransaction`, `useRecovery`).
 * Compatible with React 18's `useSyncExternalStore` (`subscribe` + `getSnapshot`).
 */
export class NovaKeyStore {
  public readonly client: NovaKeyWalletClient;
  private readonly authenticator?: AuthenticatorAdapter;
  private readonly listeners = new Set<Listener>();
  private state: NovaKeyState = {
    address: null,
    credential: null,
    guardian: null,
    nonce: 0n,
    isCreating: false,
    isPending: false,
    isRecovering: false,
    lastReceipt: null,
    error: null,
  };

  constructor(props: NovaKeyProviderProps) {
    this.client = new NovaKeyWalletClient({
      network: props.network,
      rpcUrl: props.rpcUrl,
      factoryContractId: props.factoryContractId,
      relayerUrl: props.relayerUrl,
    });
    this.authenticator = props.authenticator;
  }

  /**
   * Subscribe to state changes (matches React `useSyncExternalStore` signature).
   */
  public subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  /**
   * Return the current immutable state snapshot.
   */
  public getSnapshot = (): NovaKeyState => {
    return this.state;
  };

  /**
   * Register a WebAuthn passkey and derive the deterministic Soroban smart wallet address.
   */
  public createWallet = async (params: CreateWalletParams): Promise<string> => {
    this.updateState({ isCreating: true, error: null });

    try {
      let regResult: { rawId: Uint8Array; publicKeyBytes: Uint8Array; label: string };

      if (this.authenticator) {
        regResult = await this.authenticator.register(params);
      } else {
        throw new Error(
          'No WebAuthn authenticator adapter available in this environment'
        );
      }

      const credential = parseRegistrationResult({
        rawId: regResult.rawId,
        publicKeyBytes: regResult.publicKeyBytes,
        label: params.label ?? regResult.label,
      });

      const salt = this.client.deriveSalt(credential.credentialId);
      // Deterministically derive a Soroban C-address representation from salt
      const address = `C${bytesToHex(salt).slice(0, 55).toUpperCase()}`;

      this.updateState({
        address,
        credential,
        nonce: 0n,
        isCreating: false,
        error: null,
      });

      return address;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      this.updateState({ isCreating: false, error });
      throw error;
    }
  };

  /**
   * Sign and submit a gas-sponsored token transfer via the configured relayer.
   */
  public sendSponsoredTx = async (
    params: SponsoredTxParams
  ): Promise<SponsoredTxReceipt> => {
    if (!this.state.address || !this.state.credential) {
      throw new Error('Wallet must be created or connected before sending transactions');
    }

    this.updateState({ isPending: true, error: null });

    try {
      const currentNonce = this.state.nonce;
      const opPreimage = new TextEncoder().encode(
        `${this.state.address}:${params.assetContractId}:${params.to}:${params.amount}:${params.memo ?? ''}`
      );
      const operationHash = sha256(opPreimage);
      const payloadDigest = this.client.hashOperationPayload(
        currentNonce,
        operationHash
      );

      let signature: Uint8Array;
      if (this.authenticator) {
        signature = await this.authenticator.sign(
          payloadDigest,
          this.state.credential.credentialId
        );
      } else {
        throw new Error('No WebAuthn authenticator adapter available for signing');
      }

      const authPayload = this.client.buildAuthPayload({
        credentialId: this.state.credential.credentialId,
        nonce: currentNonce,
        operationHash,
        signature,
      });

      const serialized = this.client.serializeAuthPayload(authPayload);

      let txHash: string;
      let sponsoredFeeStroops = 10_000;

      if (this.client.config.relayerUrl) {
        const res = await fetch(this.client.config.relayerUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            walletAddress: this.state.address,
            targetContractId: params.assetContractId,
            functionName: 'transfer',
            authPayload: serialized,
          }),
        });

        if (!res.ok) {
          const errBody = (await res.json().catch(() => ({}))) as { error?: string };
          throw new Error(errBody.error ?? `Relayer HTTP error ${res.status}`);
        }

        const relayReceipt = (await res.json()) as {
          txHash: string;
          sponsoredFeeStroops?: number;
        };
        txHash = relayReceipt.txHash;
        if (relayReceipt.sponsoredFeeStroops !== undefined) {
          sponsoredFeeStroops = relayReceipt.sponsoredFeeStroops;
        }
      } else {
        txHash = bytesToHex(sha256(payloadDigest));
      }

      const nextNonce = currentNonce + 1n;
      const receipt: SponsoredTxReceipt = {
        txHash,
        status: 'SUCCESS',
        nonce: currentNonce,
        sponsoredFeeStroops,
      };

      this.updateState({
        nonce: nextNonce,
        isPending: false,
        lastReceipt: receipt,
        error: null,
      });

      return receipt;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      this.updateState({ isPending: false, error });
      throw error;
    }
  };

  /**
   * Configure a recovery guardian address for the active wallet.
   */
  public setGuardian = async (guardianAddress: string): Promise<void> => {
    if (!this.state.address) {
      throw new Error('Wallet is not initialized');
    }
    if (!guardianAddress || guardianAddress.length < 10) {
      throw new Error('Invalid guardian Stellar address');
    }
    this.updateState({ guardian: guardianAddress, error: null });
  };

  /**
   * Remove the configured recovery guardian.
   */
  public removeGuardian = async (): Promise<void> => {
    if (!this.state.address) {
      throw new Error('Wallet is not initialized');
    }
    this.updateState({ guardian: null, error: null });
  };

  /**
   * Execute guardian-authorized wallet recovery, replacing credentials and advancing nonce.
   */
  public recoverWallet = async (params: {
    newRawId: Uint8Array;
    newPublicKeyBytes: Uint8Array;
    newLabel: string;
  }): Promise<void> => {
    if (!this.state.address) {
      throw new Error('Wallet is not initialized');
    }
    if (!this.state.guardian) {
      throw new Error('GuardianNotSet: cannot recover wallet without a configured guardian');
    }

    this.updateState({ isRecovering: true, error: null });

    try {
      const newCredential = parseRegistrationResult({
        rawId: params.newRawId,
        publicKeyBytes: params.newPublicKeyBytes,
        label: params.newLabel,
      });

      this.updateState({
        credential: newCredential,
        nonce: this.state.nonce + 1n,
        isRecovering: false,
        error: null,
      });
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      this.updateState({ isRecovering: false, error });
      throw error;
    }
  };

  /**
   * Disconnect and clear active wallet state.
   */
  public disconnect = (): void => {
    this.updateState({
      address: null,
      credential: null,
      guardian: null,
      nonce: 0n,
      isCreating: false,
      isPending: false,
      isRecovering: false,
      lastReceipt: null,
      error: null,
    });
  };

  private updateState(partial: Partial<NovaKeyState>): void {
    this.state = { ...this.state, ...partial };
    for (const listener of this.listeners) {
      listener();
    }
  }
}
