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

  // 3. Derive deterministic deployment salt
  const salt = client.deriveSalt(mockCredentialId);
  console.log('3. Deterministic Deployment Salt (SHA-256):');
  console.log(`   Salt: ${bytesToHex(salt)}\n`);

  // 4. Construct Transaction Intent Payload
  const nonce = 0n;
  const mockOperationHash = hexToBytes(
    'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
  );

  const payloadHash = client.hashOperationPayload(nonce, mockOperationHash);
  console.log('4. Transaction Signing Digest:');
  console.log(`   Nonce:        ${nonce}`);
  console.log(`   Operation:    ${bytesToHex(mockOperationHash)}`);
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
    operationHash: mockOperationHash,
    signature: normalizedSig,
  });

  console.log('5. Full AuthPayload ready for Soroban __check_auth:');
  console.log(`   Signature Length: ${authPayload.signature.length} bytes (compact low-s)`);
  console.log(`   Nonce Validated:  ${authPayload.signed.nonce}`);
  console.log(`   Credential ID:    ${bytesToHex(authPayload.credentialId)}\n`);

  // 6. Submit to Gas-Sponsoring Relayer Engine (@novakey/relayer-node)
  const relayer = new RelayerEngine({ maxFeeStroops: 50_000 });
  const walletAddress = `C${bytesToHex(salt).slice(0, 55).toUpperCase()}`;
  const receipt = await relayer.relay({
    walletAddress,
    targetContractId: 'CUSDC000000000000000000000000000000000000000000000000000',
    functionName: 'transfer',
    authPayload: client.serializeAuthPayload(authPayload),
    requestedFeeStroops: 10_000,
  });

  console.log('6. Relayer Gas-Sponsored Receipt:');
  console.log(`   Wallet Address:   ${receipt.walletAddress}`);
  console.log(`   Transaction Hash: ${receipt.txHash}`);
  console.log(`   Sponsored Fee:    ${receipt.sponsoredFeeStroops} stroops`);
  console.log(`   Status:           ${receipt.status}\n`);

  console.log('✅ Flow simulation completed successfully.');
}

main().catch(console.error);
