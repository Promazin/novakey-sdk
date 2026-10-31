/**
 * Example: Basic NovaKey Smart Wallet Lifecycle Flow
 *
 * Demonstrates:
 * 1. Initializing the NovaKeyWalletClient
 * 2. Deriving a deterministic wallet address
 * 3. Constructing and signing transaction authorization payloads
 * 4. Normalizing ECDSA signatures to compact low-s format
 */

import {
  NovaKeyWalletClient,
  P256_SPKI_HEADER,
  bytesToHex,
  hexToBytes,
  parseRegistrationResult,
  rawToDerSignature,
  derToRawSignature,
} from '../packages/novakey-core/src/index.ts';
import { RelayerEngine } from '../packages/novakey-relayer-node/src/index.ts';

async function main() {
  console.log('🗝️  NovaKey SDK - End-to-End Smart Wallet Flow Example\n');

  // 1. Initialize SDK Client
  const client = new NovaKeyWalletClient({
    network: 'testnet',
    rpcUrl: 'https://soroban-testnet.stellar.org',
    factoryContractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
  });
  console.log('1. Client initialized for Stellar Testnet.');

  // 2. Parse a standard 91-byte WebAuthn SPKI Passkey Credential
  const mockCredentialId = hexToBytes('0102030405060708090a0b0c0d0e0f10'); // 16 bytes
  const spkiPublicKey = new Uint8Array(91);
  spkiPublicKey.set(P256_SPKI_HEADER, 0);
  spkiPublicKey[26] = 0x04; // uncompressed prefix
  spkiPublicKey.fill(0x5a, 27);

  const credential = parseRegistrationResult({
    rawId: mockCredentialId,
    publicKeyBytes: spkiPublicKey,
    label: 'MacBook Pro TouchID',
  });

  const formatted = client.formatCredentialArgs(credential);
  console.log('2. Device Credential Registered:');
  console.log(`   Label:          ${formatted.label}`);
  console.log(`   Credential ID:  ${formatted.credentialIdHex}`);
  console.log(`   Public Key:     ${formatted.publicKeyHex.slice(0, 20)}...\n`);

  // 3. Derive deterministic deployment salt and predict wallet address
  const salt = client.deriveSalt(mockCredentialId);
  const predictedAddress = client.predictWalletAddress(mockCredentialId);
  console.log('3. Deterministic Deployment Salt & Address Prediction:');
  console.log(`   Salt:              ${bytesToHex(salt)}`);
  console.log(`   Predicted Address: ${predictedAddress}\n`);

  // 4. Construct Transfer Operation Intent Payload
  const nonce = 0n;
  const transferOp = client.buildTransferOperation({
    walletAddress: predictedAddress,
    assetContractId: 'CUSDC000000000000000000000000000000000000000000000000000',
    to: 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
    amount: '25.00',
    memo: 'Cross-border remittance',
  });

  const payloadHash = client.hashOperationPayload(nonce, transferOp.operationHash);
  console.log('4. Transaction Signing Digest:');
  console.log(`   Nonce:        ${nonce}`);
  console.log(`   Operation:    ${bytesToHex(transferOp.operationHash)}`);
  console.log(`   Payload Hash: ${bytesToHex(payloadHash)}\n`);

  // 5. Build Compact Low-s Signature (mirroring WebAuthn DER conversion)
  const mockCompactSig = new Uint8Array(64);
  mockCompactSig.fill(0x77);

  // Demonstrate DER roundtrip
  const derSig = rawToDerSignature(mockCompactSig);
  const normalizedSig = derToRawSignature(derSig);

  const authPayload = client.buildAuthPayload({
    credentialId: mockCredentialId,
    nonce,
    operationHash: transferOp.operationHash,
    signature: normalizedSig,
  });

  console.log('5. Full AuthPayload ready for Soroban __check_auth:');
  console.log(`   Signature Length: ${authPayload.signature.length} bytes (compact low-s)`);
  console.log(`   Nonce Validated:  ${authPayload.signed.nonce}`);
  console.log(`   Credential ID:    ${bytesToHex(authPayload.credentialId)}\n`);

  // 6. Submit to Gas-Sponsoring Relayer Engine with Dry-Run Simulation & Idempotency
  const relayer = new RelayerEngine({ maxFeeStroops: 50_000 });
  const serializedAuth = client.serializeAuthPayload(authPayload);

  // Dry-run simulation first
  const sim = relayer.simulate({
    walletAddress: predictedAddress,
    targetContractId: 'CUSDC000000000000000000000000000000000000000000000000000',
    functionName: 'transfer',
    authPayload: serializedAuth,
    requestedFeeStroops: 10_000,
  });
  console.log('6. Pre-flight Simulation:');
  console.log(`   Status:           ${sim.status}`);
  console.log(`   Estimated Fee:    ${sim.estimatedFeeStroops} stroops`);
  console.log(`   Predicted Nonce:  ${sim.predictedNonce}\n`);

  // Execute relay with idempotency key
  const receipt = await relayer.relay({
    walletAddress: predictedAddress,
    targetContractId: 'CUSDC000000000000000000000000000000000000000000000000000',
    functionName: 'transfer',
    authPayload: serializedAuth,
    requestedFeeStroops: 10_000,
    idempotencyKey: 'tx-req-transfer-001',
  });

  console.log('7. Relayer Gas-Sponsored Receipt:');
  console.log(`   Wallet Address:   ${receipt.walletAddress}`);
  console.log(`   Transaction Hash: ${receipt.txHash}`);
  console.log(`   Sponsored Fee:    ${receipt.sponsoredFeeStroops} stroops`);
  console.log(`   Next Nonce:       ${relayer.getLatestNonce(predictedAddress)}`);
  console.log(`   Status:           ${receipt.status}\n`);

  console.log('✅ Flow simulation completed successfully.');
}

main().catch(console.error);
