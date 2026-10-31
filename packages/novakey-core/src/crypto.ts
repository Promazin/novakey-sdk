import { createHash, createPublicKey, verify } from 'node:crypto';

/**
 * Curve order (n) for NIST P-256 / secp256r1.
 */
export const SECP256R1_N = BigInt(
  '0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'
);

/**
 * Half curve order for canonical low-s normalization (BIP-62 standard).
 */
export const SECP256R1_HALF_N = SECP256R1_N / 2n;

/**
 * Parse an ASN.1 DER-encoded ECDSA signature and convert to 64-byte compact (r || s).
 * Enforces canonical low-s normalization as required by Soroban host functions.
 *
 * @param der - ASN.1 DER signature bytes from WebAuthn authenticator
 * @returns 64-byte Uint8Array containing r (32 bytes) || s (32 bytes)
 */
export function derToRawSignature(der: Uint8Array): Uint8Array {
  if (der.length < 8) {
    throw new Error('Invalid DER signature: buffer too short');
  }

  let offset = 0;

  if (der[offset++] !== 0x30) {
    throw new Error('Invalid DER signature: missing sequence tag 0x30');
  }

  // Length of sequence
  let seqLen = der[offset++];
  if (seqLen & 0x80) {
    const lenBytes = seqLen & 0x7f;
    if (lenBytes === 0 || lenBytes > 2 || offset + lenBytes > der.length) {
      throw new Error('Invalid DER signature: malformed sequence length');
    }
    seqLen = 0;
    for (let i = 0; i < lenBytes; i++) {
      seqLen = (seqLen << 8) | der[offset++];
    }
  }

  if (offset + seqLen !== der.length) {
    throw new Error('Invalid DER signature: sequence length mismatch');
  }

  // Parse r
  if (der[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: missing integer tag for r');
  }
  const rLen = der[offset++];
  if (rLen === 0 || offset + rLen > der.length) {
    throw new Error('Invalid DER signature: invalid r length');
  }
  const rBytes = der.slice(offset, offset + rLen);
  offset += rLen;

  // Parse s
  if (der[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: missing integer tag for s');
  }
  const sLen = der[offset++];
  if (sLen === 0 || offset + sLen !== der.length) {
    throw new Error('Invalid DER signature: invalid s length');
  }
  const sBytes = der.slice(offset, offset + sLen);

  const r = bytesToBigInt(rBytes);
  let s = bytesToBigInt(sBytes);

  if (r <= 0n || r >= SECP256R1_N) {
    throw new Error('Invalid DER signature: r out of curve order bounds');
  }
  if (s <= 0n || s >= SECP256R1_N) {
    throw new Error('Invalid DER signature: s out of curve order bounds');
  }

  // Normalize s to low-s
  if (s > SECP256R1_HALF_N) {
    s = SECP256R1_N - s;
  }

  const raw = new Uint8Array(64);
  raw.set(bigIntTo32Bytes(r), 0);
  raw.set(bigIntTo32Bytes(s), 32);

  return raw;
}

/**
 * Verify whether a 64-byte compact signature (r || s) has valid curve scalars
 * and is already normalized to canonical low-s form.
 */
export function isLowSSignature(raw: Uint8Array): boolean {
  if (raw.length !== 64) {
    return false;
  }
  const r = bytesToBigInt(raw.slice(0, 32));
  const s = bytesToBigInt(raw.slice(32, 64));
  return r > 0n && r < SECP256R1_N && s > 0n && s <= SECP256R1_HALF_N;
}

/**
 * Convert 64-byte compact signature (r || s) back into ASN.1 DER format.
 */
export function rawToDerSignature(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) {
    throw new Error('Raw signature must be exactly 64 bytes');
  }

  const rBytes = trimAndPadDerInteger(raw.slice(0, 32));
  const sBytes = trimAndPadDerInteger(raw.slice(32, 64));

  const totalLen = 2 + rBytes.length + 2 + sBytes.length;
  const der = new Uint8Array(2 + totalLen);

  let offset = 0;
  der[offset++] = 0x30;
  der[offset++] = totalLen;

  der[offset++] = 0x02;
  der[offset++] = rBytes.length;
  der.set(rBytes, offset);
  offset += rBytes.length;

  der[offset++] = 0x02;
  der[offset++] = sBytes.length;
  der.set(sBytes, offset);

  return der;
}

/**
 * Hash a nonce and operation hash with SHA-256, matching `crypto::hash_payload` in the Soroban contract.
 *
 * Layout: `SHA-256(nonce_le_8_bytes || operation_hash_32_bytes)`
 */
export function hashPayload(nonce: bigint, operationHash: Uint8Array): Uint8Array {
  if (operationHash.length !== 32) {
    throw new Error('Operation hash must be exactly 32 bytes');
  }

  // 8 bytes little-endian nonce
  const nonceBytes = new Uint8Array(8);
  const view = new DataView(nonceBytes.buffer);
  view.setBigUint64(0, nonce, true);

  const data = new Uint8Array(8 + 32);
  data.set(nonceBytes, 0);
  data.set(operationHash, 8);

  return sha256(data);
}

/**
 * Derive deterministic 32-byte salt from a 16-byte credential ID.
 * Matches `FactoryContract::derive_salt`.
 */
export function deriveCredentialSalt(credentialId: Uint8Array): Uint8Array {
  if (credentialId.length !== 16) {
    throw new Error('Credential ID must be exactly 16 bytes');
  }
  return sha256(credentialId);
}

/**
 * Compute SHA-256 hash of data.
 */
export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/**
 * Convert BigInt to fixed 32-byte big-endian Uint8Array.
 */
export function bigIntTo32Bytes(val: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let v = val;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

/**
 * Convert big-endian byte array to BigInt.
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < bytes.length; i++) {
    v = (v << 8n) | BigInt(bytes[i]);
  }
  return v;
}

/**
 * DER integer encoding helper: strips leading zero padding and prepends 0x00 if highest bit is set.
 */
function trimAndPadDerInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  const trimmed = bytes.slice(start);
  if (trimmed[0] & 0x80) {
    const padded = new Uint8Array(trimmed.length + 1);
    padded[0] = 0x00;
    padded.set(trimmed, 1);
    return padded;
  }
  return trimmed;
}

/**
 * Convert byte array to hexadecimal string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hexadecimal string to byte array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error('Hex string must have an even length');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`Invalid hex character at offset ${i * 2}`);
    }
    bytes[i] = byte;
  }
  return bytes;
}

/**
 * Encode byte array into a URL-safe Base64 (base64url) string without padding.
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/**
 * Decode a URL-safe Base64 (base64url) string into a Uint8Array.
 */
export function base64UrlToBytes(base64url: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(base64url)) {
    throw new Error('Invalid base64url string');
  }
  return new Uint8Array(Buffer.from(base64url, 'base64url'));
}

/**
 * Standard ASN.1 DER SubjectPublicKeyInfo (SPKI) 26-byte prefix for P-256 (secp256r1) uncompressed keys.
 */
export const P256_SPKI_HEADER = new Uint8Array([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);

/**
 * Standard RFC 4648 Base32 alphabet used by Stellar StrKey.
 */
const RFC4648_BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Compute CRC16-XMODEM checksum used in Stellar StrKey encoding.
 */
export function crc16Xmodem(data: Uint8Array): number {
  let crc = 0x0000;
  for (const byte of data) {
    let code = (crc >>> 8) & 0xff;
    code ^= byte & 0xff;
    code ^= code >>> 4;
    crc = (crc << 8) & 0xffff;
    crc ^= code;
    code = (code << 5) & 0xffff;
    crc ^= code;
    code = (code << 7) & 0xffff;
    crc ^= code;
  }
  return crc;
}

/**
 * Encode bytes to RFC 4648 Base32 string (no padding).
 */
export function base32Encode(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < data.length; i++) {
    value = (value << 8) | data[i];
    bits += 8;
    while (bits >= 5) {
      output += RFC4648_BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += RFC4648_BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/**
 * Decode RFC 4648 Base32 string into Uint8Array.
 */
export function base32Decode(str: string): Uint8Array {
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (let i = 0; i < str.length; i++) {
    const idx = RFC4648_BASE32_ALPHABET.indexOf(str[i]);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character '${str[i]}' at index ${i}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

/**
 * Encode a 32-byte Soroban contract ID hash into a canonical Stellar contract address (StrKey, 'C...').
 */
export function encodeContractAddress(contractId: Uint8Array): string {
  if (contractId.length !== 32) {
    throw new Error(`Contract ID must be 32 bytes, got ${contractId.length}`);
  }
  const payload = new Uint8Array(33);
  payload[0] = 0x10; // StrKey contract version byte (16)
  payload.set(contractId, 1);

  const checksum = crc16Xmodem(payload);
  const full = new Uint8Array(35);
  full.set(payload, 0);
  full[33] = checksum & 0xff;
  full[34] = (checksum >>> 8) & 0xff;

  return base32Encode(full);
}

/**
 * Decode a canonical Stellar contract address ('C...') into its 32-byte contract ID hash.
 */
export function decodeContractAddress(address: string): Uint8Array {
  if (typeof address !== 'string' || address.length !== 56 || !address.startsWith('C')) {
    throw new Error('Invalid Stellar contract address format (expected 56 characters starting with C)');
  }
  const decoded = base32Decode(address);
  if (decoded.length !== 35 || decoded[0] !== 0x10) {
    throw new Error('Invalid StrKey payload length or contract version prefix');
  }
  const payload = decoded.subarray(0, 33);
  const calculatedCrc = crc16Xmodem(payload);
  const storedCrc = decoded[33] | (decoded[34] << 8);
  if (calculatedCrc !== storedCrc) {
    throw new Error('Invalid Stellar contract address: CRC16 checksum verification failed');
  }
  return decoded.slice(1, 33);
}

/**
 * Predict the deterministic Soroban contract address for a contract deployed via `deployer.with_current_contract(salt)`.
 * Layout: `SHA-256(deployer_contract_id_32_bytes || salt_32_bytes)` encoded as StrKey.
 */
export function predictContractAddress(deployerAddress: string, salt: Uint8Array): string {
  if (salt.length !== 32) {
    throw new Error(`Deployment salt must be 32 bytes, got ${salt.length}`);
  }
  const deployerContractId = decodeContractAddress(deployerAddress);
  const buffer = new Uint8Array(64);
  buffer.set(deployerContractId, 0);
  buffer.set(salt, 32);
  const addressHash = sha256(buffer);
  return encodeContractAddress(addressHash);
}

/**
 * Verify an ECDSA secp256r1 signature over a 32-byte SHA-256 digest using Node/Web Crypto.
 * Supports both 64-byte compact (r || s) and ASN.1 DER signatures.
 */
export function verifySecp256r1Digest(
  publicKey: Uint8Array,
  digest: Uint8Array,
  signature: Uint8Array
): boolean {
  if (publicKey.length !== 65 || publicKey[0] !== 0x04) {
    throw new Error('Public key must be 65-byte uncompressed secp256r1 (0x04 prefix)');
  }
  if (digest.length !== 32) {
    throw new Error(`Digest must be 32 bytes, got ${digest.length}`);
  }

  const derSig = signature.length === 64 ? rawToDerSignature(signature) : signature;
  const spki = new Uint8Array(91);
  spki.set(P256_SPKI_HEADER, 0);
  spki.set(publicKey, 26);

  try {
    const keyObj = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
    return verify(null, digest, keyObj, derSig);
  } catch {
    return false;
  }
}
