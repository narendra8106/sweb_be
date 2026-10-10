const crypto = require('crypto');

const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

function computeSha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function verifyIntegrityDigest(expectedHash, actualBytes) {
  if (!/^[a-f0-9]{64}$/i.test(String(expectedHash || ''))) return false;
  const actualHash = computeSha256(actualBytes);
  return crypto.timingSafeEqual(Buffer.from(expectedHash, 'hex'), Buffer.from(actualHash, 'hex'));
}

function generateEd25519Keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const publicDer = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  return {
    private_key_pem: privateKey,
    public_key_pem: publicKey,
    public_key_hex: publicDer.subarray(publicDer.length - 32).toString('hex'),
  };
}

function signModuleBytes(privateKeyPem, moduleBytes) {
  return crypto.sign(null, moduleBytes, crypto.createPrivateKey(privateKeyPem)).toString('hex');
}

function verifyModuleSignature(publicKeyString, moduleBytes, signatureHex) {
  try {
    const keyString = String(publicKeyString || '').trim();
    const publicKey = keyString.startsWith('-----BEGIN PUBLIC KEY-----')
      ? crypto.createPublicKey(keyString)
      : crypto.createPublicKey({
        key: Buffer.concat([
          Buffer.from('302a300506032b6570032100', 'hex'),
          Buffer.from(keyString, 'hex'),
        ]),
        format: 'der',
        type: 'spki',
      });
    if (!/^[a-f0-9]{128}$/i.test(String(signatureHex || ''))) return false;
    return crypto.verify(null, moduleBytes, publicKey, Buffer.from(signatureHex, 'hex'));
  } catch {
    return false;
  }
}

function canonicalizeJson(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalizeJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`).join(',')}}`;
}

function computeAuditEntryHash(entry) {
  const content = [
    entry.sequence_number,
    entry.timestamp,
    entry.actor_username,
    entry.event_type,
    entry.resource_type,
    entry.resource_id,
    entry.payload_hash,
    entry.previous_hash,
  ].join('|');
  return computeSha256(content);
}

async function appendAuditLog(pool, actorUsername, eventType, resourceType, resourceId, details = {}) {
  const connection = await pool.getConnection();
  let lockAcquired = false;
  try {
    const [lockRows] = await connection.query("SELECT GET_LOCK('wasm_audit_chain', 10) AS acquired");
    if (Number(lockRows[0]?.acquired) !== 1) {
      throw new Error('Unable to acquire the audit-chain write lock');
    }
    lockAcquired = true;
    const [rows] = await connection.query(
      'SELECT sequence_number, entry_hash FROM audit_log ORDER BY sequence_number DESC LIMIT 1',
    );
    const sequenceNumber = rows.length ? Number(rows[0].sequence_number) + 1 : 1;
    const timestamp = new Date().toISOString();
    const entry = {
      sequence_number: sequenceNumber,
      timestamp,
      actor_username: actorUsername,
      event_type: eventType,
      resource_type: resourceType,
      resource_id: String(resourceId),
      details_json: details,
      payload_hash: computeSha256(canonicalizeJson(details)),
      previous_hash: rows.length ? rows[0].entry_hash : GENESIS_PREV_HASH,
    };
    entry.entry_hash = computeAuditEntryHash(entry);
    await connection.execute(
      `INSERT INTO audit_log
        (sequence_number, timestamp, actor_username, event_type, resource_type, resource_id,
         details_json, payload_hash, previous_hash, entry_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        entry.sequence_number, entry.timestamp, entry.actor_username, entry.event_type,
        entry.resource_type, entry.resource_id, JSON.stringify(details), entry.payload_hash,
        entry.previous_hash, entry.entry_hash,
      ],
    );
    return entry;
  } finally {
    if (lockAcquired) await connection.query("SELECT RELEASE_LOCK('wasm_audit_chain')");
    connection.release();
  }
}

async function verifyAuditChain(pool) {
  const [entries] = await pool.query('SELECT * FROM audit_log ORDER BY sequence_number ASC');
  if (!entries.length) {
    return {
      is_valid: true,
      total_blocks: 0,
      status: 'empty',
      message: 'Audit chain is empty. No records to verify.',
      broken_block_index: null,
    };
  }

  let expectedPreviousHash = GENESIS_PREV_HASH;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const sequenceNumber = index + 1;
    if (Number(entry.sequence_number) !== sequenceNumber) {
      return {
        is_valid: false,
        total_blocks: entries.length,
        status: 'corrupted',
        message: `Sequence number gap at block ${index}: expected ${sequenceNumber}, found ${entry.sequence_number}`,
        broken_block_index: Number(entry.sequence_number),
      };
    }
    if (entry.previous_hash !== expectedPreviousHash) {
      return {
        is_valid: false,
        total_blocks: entries.length,
        status: 'corrupted',
        message: `Hash chain broken at block ${entry.sequence_number}: previous_hash mismatch`,
        broken_block_index: Number(entry.sequence_number),
      };
    }

    const details = typeof entry.details_json === 'string' ? JSON.parse(entry.details_json) : entry.details_json;
    const payloadHash = computeSha256(canonicalizeJson(details || {}));
    if (payloadHash !== entry.payload_hash) {
      return {
        is_valid: false,
        total_blocks: entries.length,
        status: 'corrupted',
        message: `Payload tampered at block ${entry.sequence_number}: data content has been modified`,
        broken_block_index: Number(entry.sequence_number),
      };
    }
    if (computeAuditEntryHash(entry) !== entry.entry_hash) {
      return {
        is_valid: false,
        total_blocks: entries.length,
        status: 'corrupted',
        message: `Block hash invalid at block ${entry.sequence_number}: signature mismatch`,
        broken_block_index: Number(entry.sequence_number),
      };
    }
    expectedPreviousHash = entry.entry_hash;
  }

  return {
    is_valid: true,
    total_blocks: entries.length,
    status: 'verified',
    message: `Cryptographic hash chain intact across all ${entries.length} blocks.`,
    latest_block_hash: entries[entries.length - 1].entry_hash,
    broken_block_index: null,
  };
}

module.exports = {
  GENESIS_PREV_HASH,
  computeSha256,
  verifyIntegrityDigest,
  generateEd25519Keypair,
  signModuleBytes,
  verifyModuleSignature,
  canonicalizeJson,
  computeAuditEntryHash,
  appendAuditLog,
  verifyAuditChain,
};
