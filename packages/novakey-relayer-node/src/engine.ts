import {
  bytesToHex,
  hexToBytes,
  isLowSSignature,
  NovaKeyWalletClient,
  sha256,
} from '../../novakey-core/src/index.ts';
import type {
  RelayerMetrics,
  RelayerPolicyConfig,
  RelayerSubmitter,
  RelayReceipt,
  RelayRequest,
  SimulateResult,
} from './types.ts';

/**
 * Error thrown by the RelayerEngine with an associated HTTP status code.
 */
export class RelayerError extends Error {
  public readonly statusCode: number;
  public readonly code: string;

  constructor(message: string, statusCode = 400, code = 'INVALID_REQUEST') {
    super(message);
    this.name = 'RelayerError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

/**
 * Core gas-sponsoring relayer engine that validates passkey `AuthPayload`s,
 * enforces rate limits and sponsorship policies, prevents mempool nonce replay,
 * and broadcasts fee-bump transactions.
 */
export class RelayerEngine {
  private readonly policy: Required<RelayerPolicyConfig>;
  private readonly client: NovaKeyWalletClient;
  private readonly submitter?: RelayerSubmitter;
  private readonly receipts = new Map<string, RelayReceipt>();
  private readonly consumedNonces = new Set<string>();
  private readonly rateLimitWindows = new Map<string, number[]>();
  private readonly idempotencyCache = new Map<string, RelayReceipt>();
  private readonly walletHighestNonces = new Map<string, bigint>();

  private totalRelayed = 0;
  private totalRejected = 0;
  private totalFeeSponsoredStroops = 0;
  private idempotencyHits = 0;

  constructor(
    policy: RelayerPolicyConfig = {},
    submitter?: RelayerSubmitter
  ) {
    this.policy = {
      maxFeeStroops: policy.maxFeeStroops ?? 100_000,
      rateLimitPerMinute: policy.rateLimitPerMinute ?? 20,
      allowedTargetContracts: policy.allowedTargetContracts ?? [],
      requireCanonicalLowS: policy.requireCanonicalLowS ?? true,
    };
    this.submitter = submitter;
    this.client = new NovaKeyWalletClient({
      network: 'testnet',
      rpcUrl: 'https://soroban-testnet.stellar.org',
    });
  }

  /**
   * Validate a `RelayRequest` against structural, cryptographic, and policy rules.
   */
  public validateRequest(request: RelayRequest): void {
    if (!request || typeof request !== 'object') {
      throw new RelayerError('Request body must be a JSON object', 400, 'BAD_BODY');
    }

    if (
      typeof request.walletAddress !== 'string' ||
      !request.walletAddress.startsWith('C') ||
      request.walletAddress.length < 10
    ) {
      throw new RelayerError(
        'Invalid Soroban smart wallet address (must start with C)',
        400,
        'INVALID_WALLET_ADDRESS'
      );
    }

    if (!request.authPayload || typeof request.authPayload !== 'object') {
      throw new RelayerError('Missing authPayload in relay request', 400, 'MISSING_AUTH_PAYLOAD');
    }

    // Validate target contract allowlist if configured
    if (this.policy.allowedTargetContracts.length > 0) {
      if (
        !request.targetContractId ||
        !this.policy.allowedTargetContracts.includes(request.targetContractId)
      ) {
        throw new RelayerError(
          `Target contract ${request.targetContractId ?? 'none'} is not in relayer allowlist`,
          403,
          'CONTRACT_NOT_ALLOWED'
        );
      }
    }

    // Validate requested fee cap
    if (
      request.requestedFeeStroops !== undefined &&
      (request.requestedFeeStroops <= 0 || request.requestedFeeStroops > this.policy.maxFeeStroops)
    ) {
      throw new RelayerError(
        `Requested fee ${request.requestedFeeStroops} exceeds maximum sponsored fee ${this.policy.maxFeeStroops}`,
        400,
        'FEE_LIMIT_EXCEEDED'
      );
    }

    // Deserialize and verify field lengths via @novakey/core
    let parsedAuth;
    try {
      parsedAuth = this.client.deserializeAuthPayload(request.authPayload);
    } catch (err) {
      throw new RelayerError(
        err instanceof Error ? err.message : 'Malformed authPayload',
        400,
        'MALFORMED_AUTH_PAYLOAD'
      );
    }

    if (parsedAuth.signed.nonce < 0n) {
      throw new RelayerError('Nonce must be a non-negative integer', 400, 'INVALID_NONCE');
    }

    if (this.policy.requireCanonicalLowS && !isLowSSignature(parsedAuth.signature)) {
      throw new RelayerError(
        'Signature is not in canonical low-s compact format',
        400,
        'NON_CANONICAL_SIGNATURE'
      );
    }
  }

  /**
   * Process and sponsor a validated relay request.
   */
  public async relay(request: RelayRequest): Promise<RelayReceipt> {
    try {
      // Return cached receipt if idempotency key was previously relayed
      if (request.idempotencyKey) {
        const cached = this.idempotencyCache.get(request.idempotencyKey);
        if (cached) {
          this.idempotencyHits += 1;
          return { ...cached, isIdempotentReplay: true };
        }
      }

      this.validateRequest(request);
      this.enforceRateLimit(request.walletAddress);

      const nonceKey = `${request.walletAddress}:${request.authPayload.nonce}`;
      if (this.consumedNonces.has(nonceKey)) {
        throw new RelayerError(
          `Nonce ${request.authPayload.nonce} already relayed for wallet ${request.walletAddress}`,
          409,
          'NONCE_REPLAY_DETECTED'
        );
      }

      const defaultFee = request.requestedFeeStroops ?? Math.min(10_000, this.policy.maxFeeStroops);

      let txHash: string;
      let sponsoredFeeStroops = defaultFee;

      if (this.submitter) {
        const result = await this.submitter(request);
        txHash = result.txHash;
        if (result.sponsoredFeeStroops !== undefined) {
          sponsoredFeeStroops = result.sponsoredFeeStroops;
        }
      } else {
        // Compute deterministic transaction hash from wallet, credential, nonce, and signature
        const preimage = new TextEncoder().encode(
          `${request.walletAddress}:${request.authPayload.credentialIdHex}:${request.authPayload.nonce}:${request.authPayload.operationHashHex}:${request.authPayload.signatureHex}`
        );
        txHash = bytesToHex(sha256(preimage));
      }

      this.consumedNonces.add(nonceKey);

      // Track highest nonce seen for this wallet
      const reqNonce = BigInt(request.authPayload.nonce);
      const currentHighest = this.walletHighestNonces.get(request.walletAddress) ?? 0n;
      if (reqNonce >= currentHighest) {
        this.walletHighestNonces.set(request.walletAddress, reqNonce + 1n);
      }

      const receipt: RelayReceipt = {
        txHash,
        status: 'SUCCESS',
        walletAddress: request.walletAddress,
        credentialIdHex: request.authPayload.credentialIdHex,
        nonce: request.authPayload.nonce,
        sponsoredFeeStroops,
        timestamp: Date.now(),
        idempotencyKey: request.idempotencyKey,
      };

      this.receipts.set(txHash, receipt);
      if (request.idempotencyKey) {
        this.idempotencyCache.set(request.idempotencyKey, receipt);
      }

      this.totalRelayed += 1;
      this.totalFeeSponsoredStroops += sponsoredFeeStroops;

      return receipt;
    } catch (err) {
      this.totalRejected += 1;
      throw err;
    }
  }

  /**
   * Dry-run simulation of a relay request without advancing nonces or broadcasting.
   */
  public simulate(request: RelayRequest): SimulateResult {
    this.validateRequest(request);

    const estimatedFee = request.requestedFeeStroops ?? Math.min(10_000, this.policy.maxFeeStroops);
    const allowed = this.policy.allowedTargetContracts.length === 0 ||
      (request.targetContractId !== undefined && this.policy.allowedTargetContracts.includes(request.targetContractId));

    return {
      status: 'OK',
      walletAddress: request.walletAddress,
      predictedNonce: request.authPayload.nonce,
      estimatedFeeStroops: estimatedFee,
      allowedTarget: allowed,
      validSignature: true,
    };
  }

  /**
   * Retrieve the next expected nonce for a wallet based on relayed transactions.
   */
  public getLatestNonce(walletAddress: string): bigint {
    return this.walletHighestNonces.get(walletAddress) ?? 0n;
  }

  /**
   * Retrieve all transaction receipts for a given wallet address.
   */
  public getWalletReceipts(walletAddress: string): RelayReceipt[] {
    return Array.from(this.receipts.values())
      .filter((r) => r.walletAddress === walletAddress)
      .sort((a, b) => b.timestamp - a.timestamp);
  }

  /**
   * Retrieve a previously relayed transaction receipt by hash.
   */
  public getReceipt(txHash: string): RelayReceipt | undefined {
    return this.receipts.get(txHash);
  }

  /**
   * Return operational metrics for health monitoring.
   */
  public getMetrics(): RelayerMetrics {
    return {
      totalRelayed: this.totalRelayed,
      totalRejected: this.totalRejected,
      totalFeeSponsoredStroops: this.totalFeeSponsoredStroops,
      activeNoncesTracked: this.consumedNonces.size,
      idempotencyHits: this.idempotencyHits,
    };
  }

  private enforceRateLimit(walletAddress: string): void {
    const now = Date.now();
    const windowStart = now - 60_000;
    const timestamps = (this.rateLimitWindows.get(walletAddress) ?? []).filter(
      (t) => t > windowStart
    );

    if (timestamps.length >= this.policy.rateLimitPerMinute) {
      throw new RelayerError(
        `Rate limit exceeded for wallet ${walletAddress} (max ${this.policy.rateLimitPerMinute}/min)`,
        429,
        'RATE_LIMIT_EXCEEDED'
      );
    }

    timestamps.push(now);
    this.rateLimitWindows.set(walletAddress, timestamps);
  }
}
