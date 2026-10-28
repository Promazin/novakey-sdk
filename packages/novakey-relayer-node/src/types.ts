import type { SerializedAuthPayload } from '../../novakey-core/src/index.ts';

/**
 * Payload submitted by a client SDK to the gas-sponsoring relayer.
 */
export interface RelayRequest {
  /** Deployed Soroban smart wallet contract address (starts with 'C') */
  walletAddress: string;
  /** Optional target contract address being invoked (e.g., USDC token contract) */
  targetContractId?: string;
  /** Optional function name being invoked on the target contract */
  functionName?: string;
  /** Serialized passkey authorization payload */
  authPayload: SerializedAuthPayload;
  /** Requested fee cap in stroops */
  requestedFeeStroops?: number;
}

/**
 * Receipt returned by the relayer once a sponsored transaction is processed.
 */
export interface RelayReceipt {
  /** 64-character hex transaction hash */
  txHash: string;
  /** Execution status */
  status: 'SUCCESS' | 'PENDING' | 'FAILED';
  /** Smart wallet address */
  walletAddress: string;
  /** Hex-encoded 16-byte credential ID that authorized the operation */
  credentialIdHex: string;
  /** Nonce consumed by this operation */
  nonce: string;
  /** Network fee sponsored by the relayer in stroops */
  sponsoredFeeStroops: number;
  /** Unix timestamp (ms) when the transaction was processed */
  timestamp: number;
}

/**
 * Security and sponsorship policy configuration for the relayer engine.
 */
export interface RelayerPolicyConfig {
  /** Maximum fee in stroops the relayer is willing to sponsor per transaction (default: 100_000) */
  maxFeeStroops?: number;
  /** Maximum sponsored transactions per wallet per 60-second window (default: 20) */
  rateLimitPerMinute?: number;
  /** Optional allowlist of target contract IDs eligible for gas sponsorship */
  allowedTargetContracts?: string[];
  /** Enforce canonical low-s signature check before forwarding to RPC (default: true) */
  requireCanonicalLowS?: boolean;
}

/**
 * Custom transaction submission handler (e.g., Soroban RPC fee-bump broadcaster).
 */
export type RelayerSubmitter = (
  request: RelayRequest
) => Promise<{ txHash: string; sponsoredFeeStroops?: number }>;

/**
 * Operational metrics reported by the relayer.
 */
export interface RelayerMetrics {
  totalRelayed: number;
  totalRejected: number;
  totalFeeSponsoredStroops: number;
}
