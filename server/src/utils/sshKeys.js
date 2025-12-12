import cbor from 'cbor';
import crypto from 'crypto';

function toBufferLoose(input) {
  if (Buffer.isBuffer(input)) return Buffer.from(input);
  if (input instanceof Uint8Array) return Buffer.from(input);
  if (typeof input === 'string') {
    const s = input.trim();
    if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) {
      return Buffer.from(s, 'hex');
    }
    try {
      // Prefer base64url first
      return Buffer.from(s, 'base64url');
    } catch {
      try { return Buffer.from(s, 'base64'); } catch { /* fallthrough */ }
    }
    return Buffer.from(s, 'utf8');
  }
  throw new Error('UNSUPPORTED_COSE_INPUT');
}

function decodeCborMapLoose(buf) {
  try {
    const m = cbor.decodeFirstSync(buf);
    if (m && typeof m.get === 'function') return m;
  } catch (e) {
    // Some inputs contain concatenated CBOR; decode all and take the first map
    try {
      const all = cbor.decodeAllSync(buf);
      const firstMap = all.find(v => v && typeof v.get === 'function');
      if (firstMap) return firstMap;
      throw e;
    } catch {
      throw e;
    }
  }
  throw new Error('INVALID_CBOR_MAP');
}

function detectKeyTypeFromCOSE(coseBuf) {
  const m = decodeCborMapLoose(toBufferLoose(coseBuf));
  const kty = m.get(1);
  const crv = m.get(-1);
  if (kty === 2 && (crv === 1 || crv === 'P-256')) return 'sk-ecdsa-sha2-nistp256@openssh.com';
  if (kty === 1 && (crv === 6 || crv === 'Ed25519')) return 'sk-ssh-ed25519@openssh.com';
  throw new Error('UNSUPPORTED_COSE_KEY');
}

function writeString(bufs, s) {
  const b = Buffer.from(s, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length, 0);
  bufs.push(len, b);
}

function writeBuf(bufs, b) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length, 0);
  bufs.push(len, Buffer.from(b));
}

function coseToOpenSSHFidoPub(coseBuf, keyType, comment, rpId) {
  const m = decodeCborMapLoose(toBufferLoose(coseBuf));
  const kty = m.get(1);
  // Use 'ssh:' for OpenSSH compatibility (ssh-keygen -K requirement)
  const application = 'ssh:';
  
  if (keyType === 'sk-ecdsa-sha2-nistp256@openssh.com') {
    if (kty !== 2) throw new Error('UNSUPPORTED_COSE_KEY');
    let x = Buffer.from(m.get(-2));
    let y = Buffer.from(m.get(-3));
    const pad32 = (b) => {
      if (b.length === 32) return b;
      if (b.length > 32) return Buffer.from(b.slice(b.length - 32));
      const pad = Buffer.alloc(32 - b.length, 0);
      return Buffer.concat([pad, b]);
    };
    x = pad32(x);
    y = pad32(y);
    const q = Buffer.concat([Buffer.from([0x04]), x, y]);
    const parts = [];
    writeString(parts, 'sk-ecdsa-sha2-nistp256@openssh.com');
    writeString(parts, 'nistp256');
    writeBuf(parts, q);
    writeString(parts, application);
    const blob = Buffer.concat(parts);
    const b64 = blob.toString('base64');
    const line = `sk-ecdsa-sha2-nistp256@openssh.com ${b64}${comment ? ' ' + comment : ''}`;
    return line;
  } else if (keyType === 'sk-ssh-ed25519@openssh.com') {
    if (kty !== 1) throw new Error('UNSUPPORTED_COSE_KEY');
    const pk = Buffer.from(m.get(-2)); // Ed25519 public key (32 bytes)
    if (pk.length !== 32) throw new Error('INVALID_ED25519_PUB');
    const parts = [];
    writeString(parts, 'sk-ssh-ed25519@openssh.com');
    writeBuf(parts, pk);
    writeString(parts, application);
    const blob = Buffer.concat(parts);
    const b64 = blob.toString('base64');
    const line = `sk-ssh-ed25519@openssh.com ${b64}${comment ? ' ' + comment : ''}`;
    return line;
  }
  throw new Error('UNSUPPORTED_KEY_TYPE');
}

function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function packString(s) {
  const b = Buffer.isBuffer(s) ? Buffer.from(s) : Buffer.from(String(s), 'utf8');
  return Buffer.concat([u32(b.length), b]);
}

function buildSkEcdsaPublicBlobFromCOSE(coseBuf) {
  const m = decodeCborMapLoose(toBufferLoose(coseBuf));
  let x = Buffer.from(m.get(-2));
  let y = Buffer.from(m.get(-3));
  const pad32 = (b) => {
    if (b.length === 32) return b;
    if (b.length > 32) return Buffer.from(b.slice(b.length - 32));
    const pad = Buffer.alloc(32 - b.length, 0);
    return Buffer.concat([pad, b]);
  };
  x = pad32(x);
  y = pad32(y);
  const q = Buffer.concat([Buffer.from([0x04]), x, y]);
  const parts = [];
  // string keytype
  parts.push(packString('sk-ecdsa-sha2-nistp256@openssh.com'));
  // string sk-provider
  parts.push(packString('webauthn-sk'));
  // string curve
  parts.push(packString('nistp256'));
  // string public EC point
  parts.push(packString(q));
  return Buffer.concat(parts);
}

function buildSkEd25519PublicBlobFromCOSE(coseBuf) {
  const m = decodeCborMapLoose(toBufferLoose(coseBuf));
  const x = Buffer.from(m.get(-2)); // Ed25519 public key (32 bytes)
  if (x.length !== 32) throw new Error('INVALID_ED25519_PUB');
  const parts = [];
  // string keytype
  parts.push(packString('sk-ssh-ed25519@openssh.com'));
  // string sk-provider
  parts.push(packString('webauthn-sk'));
  // string public key
  parts.push(packString(x));
  return Buffer.concat(parts);
}

function generateFidoStub({ rpId, keyType, comment, cosePublicKey, credentialId }) {
  if (!['sk-ecdsa-sha2-nistp256@openssh.com', 'sk-ssh-ed25519@openssh.com'].includes(keyType)) {
    throw new Error('UNSUPPORTED_KEY_TYPE');
  }
  if (!cosePublicKey) throw new Error('MISSING_COSE_PUBLIC_KEY');

  // Build public blob from COSE
  const pubBlob = keyType === 'sk-ecdsa-sha2-nistp256@openssh.com'
    ? buildSkEcdsaPublicBlobFromCOSE(cosePublicKey)
    : buildSkEd25519PublicBlobFromCOSE(cosePublicKey);

  // Build OpenSSH private key format: openssh-key-v1
  const header = Buffer.concat([
    Buffer.from('openssh-key-v1\0', 'binary'),
    packString('none'), // ciphername
    packString('none'), // kdfname
    packString(Buffer.alloc(0)), // kdfoptions
    u32(1), // nkeys
    packString(pubBlob),
  ]);

  // Private section
  const check = cryptoRandomU32();
  const privParts = [];
  privParts.push(u32(check), u32(check));
  // key type and public fields again (matching native OpenSSH format)
  if (keyType === 'sk-ecdsa-sha2-nistp256@openssh.com') {
    privParts.push(packString('sk-ecdsa-sha2-nistp256@openssh.com'));
    // For ECDSA-SK: curve and Q only (no provider in private section)
    const m = decodeCborMapLoose(toBufferLoose(cosePublicKey));
    const pad32 = (b) => {
      if (b.length === 32) return Buffer.from(b);
      if (b.length > 32) return Buffer.from(b.slice(b.length - 32));
      const pad = Buffer.alloc(32 - b.length, 0);
      return Buffer.concat([pad, Buffer.from(b)]);
    };
    const x = pad32(Buffer.from(m.get(-2)));
    const y = pad32(Buffer.from(m.get(-3)));
    const q = Buffer.concat([Buffer.from([0x04]), x, y]);
    privParts.push(packString('nistp256'));
    privParts.push(packString(q));
  } else {
    // sk-ssh-ed25519@openssh.com
    privParts.push(packString('sk-ssh-ed25519@openssh.com'));
    // For Ed25519-SK: raw 32-byte pubkey only
    const m = decodeCborMapLoose(toBufferLoose(cosePublicKey));
    const pk = Buffer.from(m.get(-2));
    if (pk.length !== 32) throw new Error('INVALID_ED25519_PUB');
    privParts.push(packString(pk));
  }

  // FIDO-specific fields for sk keys (matching native OpenSSH format)
  // Application: use 'ssh:' for OpenSSH compatibility (ssh-keygen -K requirement)
  privParts.push(packString('ssh:'));
  // Flags: single byte u8 (0x01 = require user presence)
  privParts.push(Buffer.from([0x01]));
  // Key handle (credentialId)
  let kh;
  if (credentialId) {
    if (/^[0-9a-fA-F]+$/.test(credentialId)) {
      kh = Buffer.from(credentialId, 'hex');
    } else {
      try { kh = Buffer.from(credentialId, 'base64url'); } catch { kh = Buffer.from(credentialId); }
    }
  } else {
    kh = Buffer.alloc(0);
  }
  privParts.push(packString(kh));
  // Reserved (empty)
  privParts.push(packString(Buffer.alloc(0)));
  // Comment
  privParts.push(packString(comment || ''));

  // padding: 1..N sequence 1,2,3... as per spec (always at least 1 and at most 8)
  let priv = Buffer.concat(privParts);
  let padLen = 8 - (priv.length % 8);
  if (padLen === 0) padLen = 8;
  const pad = Buffer.alloc(padLen);
  for (let i = 0; i < padLen; i++) pad[i] = i + 1;
  priv = Buffer.concat([priv, pad]);

  const binary = Buffer.concat([header, u32(priv.length), priv]);
  // ASCII armour with standard OpenSSH headers and 70-char base64 lines
  const b64 = binary.toString('base64');
  const wrapped = b64.match(/.{1,70}/g)?.join('\n') || b64;
  const pem = `-----BEGIN OPENSSH PRIVATE KEY-----\n${wrapped}\n-----END OPENSSH PRIVATE KEY-----\n`;
  const filename = keyType === 'sk-ecdsa-sha2-nistp256@openssh.com' ? 'id_ecdsa_sk' : 'id_ed25519_sk';
  return { filename, content: Buffer.from(pem, 'utf8') };
}

function cryptoRandomU32() {
  const b = crypto.randomBytes(4);
  return b.readUInt32BE(0);
}

export { detectKeyTypeFromCOSE, coseToOpenSSHFidoPub, generateFidoStub };
