const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('./config');
const { pool, initSchema } = require('./database');
const { schemas } = require('./schemas');
const {
  appendAuditLog,
  canonicalizeJson,
  computeSha256,
  generateEd25519Keypair,
  signModuleBytes,
  verifyAuditChain,
  verifyIntegrityDigest,
  verifyModuleSignature,
  GENESIS_PREV_HASH,
  computeAuditEntryHash,
} = require('./services/cryptoEngine');
const { compileWat, templateMetadata, templates, validateModule } = require('./services/wasmValidator');
const { executeInWorker, getWorkerHealth } = require('./services/workerManager');

if (process.env.NODE_ENV === 'production' && !config.SECRET_KEY) {
  throw new Error('SECRET_KEY must be configured in production');
}
const jwtSecret = config.SECRET_KEY || crypto.randomBytes(32).toString('hex');
const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.MAX_UPLOAD_SIZE, files: 1 },
});
const rateWindows = new Map();
let adminUserId;

const asyncRoute = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
const parseJson = (value, fallback = null) => {
  if (value === null || value === undefined) return fallback;
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
};
const asBoolean = (value) => Boolean(Number(value));

function userOut(row) {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    role: row.role,
    is_active: asBoolean(row.is_active),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function functionOut(row) {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    module_filename: row.module_filename,
    sha256_hash: row.sha256_hash,
    signature_status: row.signature_status,
    signature_ed25519: row.signature_ed25519,
    signer_key_id: row.signer_key_id,
    source_wat: row.source_wat,
    abi_metadata: parseJson(row.abi_metadata),
    status: row.status,
    module_size: Number(row.module_size),
    owner_id: row.owner_id,
    created_at: row.created_at,
  };
}

function policyOut(row) {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    max_module_size: Number(row.max_module_size),
    max_fuel: Number(row.max_fuel),
    max_memory_bytes: Number(row.max_memory_bytes),
    timeout_ms: Number(row.timeout_ms),
    max_input_bytes: Number(row.max_input_bytes),
    max_output_bytes: Number(row.max_output_bytes),
    allowed_imports: parseJson(row.allowed_imports, []),
    require_signature: asBoolean(row.require_signature),
    is_enabled: asBoolean(row.is_enabled),
  };
}

function executionOut(row) {
  return {
    id: row.id,
    function_id: row.function_id,
    user_id: row.user_id,
    policy_id: row.policy_id,
    execution_status: row.execution_status,
    input_json: parseJson(row.input_json),
    output_json: parseJson(row.output_json),
    stdout: row.stdout || '',
    stderr: row.stderr || '',
    error_message: row.error_message,
    integrity_status: row.integrity_status,
    execution_time_ms: row.execution_time_ms === null ? null : Number(row.execution_time_ms || 0),
    fuel_consumed: row.fuel_consumed === null ? null : Number(row.fuel_consumed || 0),
    memory_consumed_bytes: row.memory_consumed_bytes === null ? null : Number(row.memory_consumed_bytes || 0),
    memory_limit_bytes: row.memory_limit_bytes === null ? null : Number(row.memory_limit_bytes || 0),
    worker_exit_reason: row.worker_exit_reason || '',
    created_at: row.created_at,
    completed_at: row.completed_at,
  };
}

function eventOut(row) {
  return {
    id: row.id,
    user_id: row.user_id,
    function_id: row.function_id,
    execution_id: row.execution_id,
    event_type: row.event_type,
    severity: row.severity,
    description: row.description,
    metadata_json: parseJson(row.metadata_json),
    created_at: row.created_at,
  };
}

function auditOut(row) {
  return {
    id: row.id,
    sequence_number: Number(row.sequence_number),
    timestamp: row.timestamp,
    actor_username: row.actor_username,
    event_type: row.event_type,
    resource_type: row.resource_type,
    resource_id: row.resource_id,
    details_json: parseJson(row.details_json),
    payload_hash: row.payload_hash,
    previous_hash: row.previous_hash,
    entry_hash: row.entry_hash,
  };
}

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function rateLimit(limit, windowMs) {
  return (req, res, next) => {
    const key = `${req.ip}:${req.baseUrl}${req.path}`;
    const now = Date.now();
    let window = rateWindows.get(key);
    if (!window || now - window.startedAt >= windowMs) {
      window = { startedAt: now, count: 0 };
      rateWindows.set(key, window);
    }
    window.count += 1;
    if (window.count > limit) {
      res.set('Retry-After', String(Math.ceil((window.startedAt + windowMs - now) / 1000)));
      return res.status(429).json({ detail: 'Too many requests. Please try again later.' });
    }
    return next();
  };
}

async function authenticate(req, res, next) {
  try {
    const authorization = req.get('Authorization') || '';
    const match = authorization.match(/^Bearer\s+(.+)$/i);
    if (!match) throw httpError(401, 'Not authenticated');
    const payload = jwt.verify(match[1], jwtSecret, { algorithms: ['HS256'] });
    const [rows] = await pool.execute('SELECT * FROM users WHERE username = ? LIMIT 1', [payload.sub]);
    if (!rows.length) throw httpError(401, 'User no longer exists');
    req.user = rows[0];
    return next();
  } catch (error) {
    return next(error.status ? error : httpError(401, 'Invalid or expired authentication token'));
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return next(httpError(403, 'Administrator access required'));
  return next();
}

function canAccessFunction(user, row) {
  return user.role === 'admin' || row.owner_id === user.id || row.owner_id === adminUserId;
}

async function getFunctionById(id) {
  const [rows] = await pool.execute('SELECT * FROM functions WHERE id = ? LIMIT 1', [id]);
  return rows[0] || null;
}

async function addSecurityEvent(userId, eventType, severity, description, metadata = {}, functionId = null, executionId = null) {
  await pool.execute(
    `INSERT INTO security_events (user_id, function_id, execution_id, event_type, severity, description, metadata_json)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId, functionId, executionId, eventType, severity, description, JSON.stringify(metadata)],
  );
}

async function storeModule({ ownerId, name, description, bytes, sourceWat, metadata }) {
  await fs.mkdir(config.UPLOAD_DIR, { recursive: true });
  const filename = `${crypto.randomUUID()}.wasm`;
  const storagePath = path.join(config.UPLOAD_DIR, filename);
  await fs.writeFile(storagePath, bytes, { flag: 'wx' });

  try {
    const [result] = await pool.execute(
      `INSERT INTO functions
        (owner_id, name, description, module_filename, storage_path, sha256_hash, source_wat, abi_metadata, module_size)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        ownerId, name, description || '', filename, storagePath, computeSha256(bytes),
        sourceWat || null, JSON.stringify(metadata), bytes.length,
      ],
    );
    return functionOut(await getFunctionById(result.insertId));
  } catch (error) {
    await fs.unlink(storagePath).catch(() => { });
    throw error;
  }
}

function issueToken(user) {
  return jwt.sign({ sub: user.username }, jwtSecret, { algorithm: 'HS256', expiresIn: config.JWT_EXPIRES_IN });
}

async function seedPolicy(policy, legacyColumns = {}) {
  const [rows] = await pool.execute('SELECT id FROM execution_policies WHERE name = ? LIMIT 1', [policy.name]);
  if (rows.length) return;
  const columns = [
    'name', 'description', 'max_module_size', 'max_fuel', 'max_memory_bytes', 'timeout_ms',
    'max_input_bytes', 'max_output_bytes', 'allowed_imports', 'require_signature', 'is_enabled',
  ];
  const values = [
    policy.name, policy.description, policy.max_module_size, policy.max_fuel,
    policy.max_memory_bytes, policy.timeout_ms, policy.max_input_bytes,
    policy.max_output_bytes, JSON.stringify(policy.allowed_imports), policy.require_signature, policy.is_enabled ?? true,
  ];

  if (legacyColumns.legacyPolicyName) {
    columns.push('policy_name');
    values.push(policy.name);
  }
  if (legacyColumns.legacyPolicyJson) {
    columns.push('policy_json');
    values.push(JSON.stringify({
      ...policy,
      max_memory_mb: Math.ceil(policy.max_memory_bytes / (1024 * 1024)),
      max_execution_ms: policy.timeout_ms,
      max_stack_height: 128,
      allow_network: false,
      allow_filesystem: false,
      allow_environment: false,
    }));
  }

  await pool.execute(
    `INSERT INTO execution_policies (${columns.map((column) => `\`${column}\``).join(', ')})
     VALUES (${columns.map(() => '?').join(', ')})`,
    values,
  );
}

async function initialize() {
  const legacyColumns = await initSchema();
  const [adminRows] = await pool.execute('SELECT * FROM users WHERE username = ? LIMIT 1', ['admin']);
  if (adminRows.length) {
    adminUserId = adminRows[0].id;
  } else {
    const passwordHash = await bcrypt.hash(config.DEFAULT_ADMIN_PASSWORD, 12);
    const [created] = await pool.execute(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
      ['admin', config.DEFAULT_ADMIN_EMAIL, passwordHash, 'admin'],
    );
    adminUserId = created.insertId;
  }

  const policies = [
    {
      name: 'Basic', description: 'Tightly constrained execution for basic workloads.',
      max_module_size: 1048576, max_fuel: 50000, max_memory_bytes: 16777216, timeout_ms: 2000,
      max_input_bytes: 1024, max_output_bytes: 4096, allowed_imports: [], require_signature: false,
    },
    {
      name: 'Standard', description: 'Balanced limits for trusted WebAssembly workloads.',
      max_module_size: 5242880, max_fuel: 200000, max_memory_bytes: 67108864, timeout_ms: 5000,
      max_input_bytes: 4096, max_output_bytes: 16384, allowed_imports: ['env.*'], require_signature: false,
    },
    {
      name: 'Strict (Signed Only)', description: 'Requires signed modules and limits imports.',
      max_module_size: 2097152, max_fuel: 100000, max_memory_bytes: 33554432, timeout_ms: 3000,
      max_input_bytes: 2048, max_output_bytes: 8192, allowed_imports: [], require_signature: true,
    },
  ];
  for (const policy of policies) await seedPolicy(policy, legacyColumns);

  for (const template of templates) {
    const [existing] = await pool.execute('SELECT id FROM functions WHERE name = ? LIMIT 1', [template.name]);
    if (existing.length) continue;
    const bytes = await compileWat(template.wat);
    const validation = await validateModule(bytes, { allowedImports: ['wasi_snapshot_preview1.sock_send'] });
    await fs.mkdir(config.EXAMPLES_DIR, { recursive: true });
    await fs.writeFile(path.join(config.EXAMPLES_DIR, `${template.id}.wasm`), bytes);
    await storeModule({
      ownerId: adminUserId,
      name: template.name,
      description: template.description,
      bytes,
      sourceWat: template.wat,
      metadata: {
        ...templateMetadata(template),
        imports: validation.imports,
        exports: validation.exports,
      },
    });
  }

  const [[auditCount]] = await pool.query('SELECT COUNT(*) AS count FROM audit_log');
  if (Number(auditCount.count) === 0) {
    await appendAuditLog(pool, 'system', 'genesis', 'system', '0', { message: 'Genesis audit record' });
  }
}

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

app.get('/api/health', (req, res) => res.json({ status: 'healthy', service: 'wasm-microvm-backend', version: '2.0.0' }));
app.get('/api/health/worker', asyncRoute(async (req, res) => res.json(await getWorkerHealth())));
app.get('/api/templates', (req, res) => res.json(templates));

app.post('/api/auth/register', rateLimit(10, 60_000), asyncRoute(async (req, res) => {
  const data = schemas.userCreate(req.body);
  const passwordHash = await bcrypt.hash(data.password, 12);
  try {
    const [result] = await pool.execute(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
      [data.username, data.email, passwordHash, 'developer'],
    );
    const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [result.insertId]);
    await appendAuditLog(pool, data.username, 'user_registered', 'user', result.insertId, { username: data.username });
    res.status(201).json({ token: issueToken(rows[0]), token_type: 'bearer' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') throw httpError(400, 'Username or email is already registered');
    throw error;
  }
}));

app.post('/api/auth/login', rateLimit(20, 60_000), asyncRoute(async (req, res) => {
  const data = schemas.userLogin(req.body);
  const [rows] = await pool.execute('SELECT * FROM users WHERE username = ? LIMIT 1', [data.username]);
  if (!rows.length || !(await bcrypt.compare(data.password, rows[0].password_hash))) {
    throw httpError(401, 'Incorrect username or password');
  }
  res.json({ token: issueToken(rows[0]), token_type: 'bearer' });
}));

app.get('/api/auth/me', authenticate, (req, res) => res.json(userOut(req.user)));
app.get('/api/users', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM users ORDER BY id');
  res.json(rows.map(userOut));
}));

app.get('/api/keys', authenticate, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    'SELECT id, owner_id, key_name, public_key, algorithm, is_active, created_at, revoked_at FROM signing_keys WHERE owner_id = ? ORDER BY id DESC',
    [req.user.id],
  );
  res.json(rows.map((row) => ({ ...row, is_active: asBoolean(row.is_active) })));
}));

app.post('/api/keys/generate', authenticate, asyncRoute(async (req, res) => {
  const { key_name: keyName } = schemas.signingKeyCreate(req.body);
  const pair = generateEd25519Keypair();
  const [result] = await pool.execute(
    'INSERT INTO signing_keys (owner_id, key_name, public_key, private_key_pem) VALUES (?, ?, ?, ?)',
    [req.user.id, keyName, pair.public_key_hex, pair.private_key_pem],
  );
  await appendAuditLog(pool, req.user.username, 'signing_key_generated', 'signing_key', result.insertId, { key_name: keyName });
  res.status(201).json({
    id: result.insertId,
    owner_id: req.user.id,
    key_name: keyName,
    public_key: pair.public_key_hex,
    algorithm: 'ed25519',
    is_active: true,
    created_at: new Date().toISOString(),
    revoked_at: null,
  });
}));

app.post('/api/functions/validate', authenticate, asyncRoute(async (req, res) => {
  const data = schemas.validationRequest(req.body);
  let bytes;
  try {
    bytes = await compileWat(data.source_wat);
  } catch (error) {
    return res.json({
      is_valid: false, sha256_hash: null, module_size: null, imports: [], exports: [],
      has_memory: false, risk_level: 'HIGH', risk_score: 100, findings: [],
      errors: [`WAT compilation failed: ${error.message}`],
    });
  }

  let allowedImports = [];
  let maxModuleSize;
  if (data.policy_id !== undefined && data.policy_id !== null) {
    const [policies] = await pool.execute('SELECT * FROM execution_policies WHERE id = ? LIMIT 1', [data.policy_id]);
    if (policies.length) {
      const policy = policyOut(policies[0]);
      allowedImports = policy.allowed_imports || [];
      maxModuleSize = policy.max_module_size;
    }
  }
  res.json(await validateModule(bytes, { allowedImports, maxModuleSize }));
}));

app.post('/api/functions/compile', authenticate, asyncRoute(async (req, res) => {
  const data = schemas.functionCreate(req.body);
  if (!data.source_wat) throw httpError(400, 'source_wat is required to compile a WebAssembly module');
  let bytes;
  try {
    bytes = await compileWat(data.source_wat);
  } catch (error) {
    throw httpError(400, `WAT compilation failed: ${error.message}`);
  }
  const [standardRows] = await pool.execute('SELECT * FROM execution_policies WHERE name = ? LIMIT 1', ['Standard']);
  const standard = standardRows[0] ? policyOut(standardRows[0]) : { allowed_imports: [] };
  const report = await validateModule(bytes, { allowedImports: standard.allowed_imports });
  if (!report.is_valid) throw httpError(400, report.errors.concat(report.findings.map((item) => item.message)).join(' '));
  const stored = await storeModule({
    ownerId: req.user.id,
    name: data.name,
    description: data.description,
    bytes,
    sourceWat: data.source_wat,
    metadata: {
      entry_point: report.exports.find((item) => item.kind === 'function')?.name || null,
      default_args: [],
      imports: report.imports,
      exports: report.exports,
    },
  });
  await appendAuditLog(pool, req.user.username, 'function_compiled', 'function', stored.id, {
    name: stored.name, sha256_hash: stored.sha256_hash,
  });
  res.status(201).json(stored);
}));

app.post('/api/functions/upload', authenticate, rateLimit(15, 60_000), upload.single('file'), asyncRoute(async (req, res) => {
  if (!req.file) throw httpError(400, 'A .wasm file is required');
  if (path.extname(req.file.originalname).toLowerCase() !== '.wasm') throw httpError(400, 'Only .wasm files are allowed');
  const report = await validateModule(req.file.buffer, { allowedImports: [] });
  if (!report.is_valid) throw httpError(400, report.errors.concat(report.findings.map((item) => item.message)).join(' '));
  const name = typeof req.body.name === 'string' && req.body.name ? req.body.name : path.basename(req.file.originalname, '.wasm');
  const stored = await storeModule({
    ownerId: req.user.id,
    name: name.slice(0, 120),
    description: String(req.body.description || ''),
    bytes: req.file.buffer,
    sourceWat: null,
    metadata: {
      entry_point: report.exports.find((item) => item.kind === 'function')?.name || null,
      default_args: [],
      imports: report.imports,
      exports: report.exports,
    },
  });
  await appendAuditLog(pool, req.user.username, 'function_uploaded', 'function', stored.id, {
    name: stored.name, sha256_hash: stored.sha256_hash,
  });
  res.status(201).json(stored);
}));

app.get('/api/functions', authenticate, asyncRoute(async (req, res) => {
  const [rows] = req.user.role === 'admin'
    ? await pool.query('SELECT * FROM functions ORDER BY created_at DESC')
    : await pool.execute('SELECT * FROM functions WHERE owner_id IN (?, ?) ORDER BY created_at DESC', [req.user.id, adminUserId]);
  res.json(rows.map(functionOut));
}));

app.get('/api/functions/:functionId', authenticate, asyncRoute(async (req, res) => {
  const row = await getFunctionById(req.params.functionId);
  if (!row) throw httpError(404, 'Function not found');
  if (!canAccessFunction(req.user, row)) throw httpError(403, 'Access denied');
  res.json(functionOut(row));
}));

app.delete('/api/functions/:functionId', authenticate, asyncRoute(async (req, res) => {
  const row = await getFunctionById(req.params.functionId);
  if (!row) throw httpError(404, 'Function not found');
  if (row.owner_id !== req.user.id && req.user.role !== 'admin') throw httpError(403, 'Access denied');
  await pool.execute('DELETE FROM functions WHERE id = ?', [row.id]);
  await fs.unlink(row.storage_path).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
  });
  await appendAuditLog(pool, req.user.username, 'function_deleted', 'function', row.id, { name: row.name });
  res.json({ ok: true, message: 'Function deleted' });
}));

app.post('/api/functions/:functionId/sign', authenticate, asyncRoute(async (req, res) => {
  const { key_id: keyId } = schemas.signFunctionRequest(req.body);
  const row = await getFunctionById(req.params.functionId);
  if (!row) throw httpError(404, 'Function not found');
  if (!canAccessFunction(req.user, row)) throw httpError(403, 'Access denied');
  const [keys] = await pool.execute(
    'SELECT * FROM signing_keys WHERE id = ? AND owner_id = ? AND is_active = 1 LIMIT 1',
    [keyId, req.user.id],
  );
  if (!keys.length || !keys[0].private_key_pem) throw httpError(400, 'Signing key was not found or is unavailable');
  const bytes = await fs.readFile(row.storage_path);
  if (!verifyIntegrityDigest(row.sha256_hash, bytes)) throw httpError(409, 'Module integrity verification failed');
  const signature = signModuleBytes(keys[0].private_key_pem, bytes);
  await pool.execute(
    'UPDATE functions SET signer_key_id = ?, signature_ed25519 = ?, signature_status = ? WHERE id = ?',
    [keyId, signature, 'verified', row.id],
  );
  await appendAuditLog(pool, req.user.username, 'function_signed', 'function', row.id, { key_id: keyId });
  res.json(functionOut(await getFunctionById(row.id)));
}));

app.post('/api/functions/:functionId/verify-signature', authenticate, asyncRoute(async (req, res) => {
  const row = await getFunctionById(req.params.functionId);
  if (!row) throw httpError(404, 'Function not found');
  if (!canAccessFunction(req.user, row)) throw httpError(403, 'Access denied');
  if (!row.signature_ed25519 || !row.signer_key_id) {
    return res.json({ is_signed: false, is_valid: false, message: 'Function is not signed.' });
  }
  const [keys] = await pool.execute('SELECT key_name, public_key FROM signing_keys WHERE id = ? LIMIT 1', [row.signer_key_id]);
  const bytes = await fs.readFile(row.storage_path);
  const isValid = keys.length > 0 && verifyIntegrityDigest(row.sha256_hash, bytes)
    && verifyModuleSignature(keys[0].public_key, bytes, row.signature_ed25519);
  res.json({
    is_signed: true,
    is_valid: isValid,
    message: isValid ? 'Signature is valid.' : 'Signature verification failed.',
    key_name: keys[0]?.key_name || null,
    signature_snippet: row.signature_ed25519.slice(0, 16),
  });
}));

app.post('/api/executions/run', authenticate, rateLimit(30, 60_000), asyncRoute(async (req, res) => {
  const data = schemas.executionRequest(req.body);
  const fn = await getFunctionById(data.module_id);
  if (!fn) throw httpError(404, 'Function not found');
  if (!canAccessFunction(req.user, fn)) throw httpError(403, 'Access denied');
  if (fn.status !== 'active') throw httpError(400, 'Function is not active');

  const [requestedPolicyRows] = data.policy_id === undefined || data.policy_id === null
    ? [[]]
    : await pool.execute('SELECT * FROM execution_policies WHERE id = ? LIMIT 1', [data.policy_id]);
  let policy = requestedPolicyRows[0];
  if (!policy) {
    const [standardRows] = await pool.execute('SELECT * FROM execution_policies WHERE name = ? LIMIT 1', ['Standard']);
    policy = standardRows[0];
  }
  if (!policy || !asBoolean(policy.is_enabled)) throw httpError(400, 'Execution policy is unavailable or disabled');
  const activePolicy = policyOut(policy);
  const inputJson = { function_name: data.function_name, args: data.args };
  const inputSize = Buffer.byteLength(JSON.stringify(inputJson), 'utf8');
  if (inputSize > activePolicy.max_input_bytes) throw httpError(400, 'Execution arguments exceed the policy input limit');

  let bytes;
  try {
    bytes = await fs.readFile(fn.storage_path);
  } catch (error) {
    if (error.code === 'ENOENT') throw httpError(500, 'Stored WebAssembly module is missing');
    throw error;
  }

  let blockedReason;
  let integrityStatus = 'verified';
  if (bytes.length > activePolicy.max_module_size) {
    blockedReason = 'Module exceeds the policy module-size limit.';
  } else if (!verifyIntegrityDigest(fn.sha256_hash, bytes)) {
    blockedReason = 'Stored module integrity verification failed.';
    integrityStatus = 'tamper_detected';
  } else {
    const validation = await validateModule(bytes, {
      allowedImports: activePolicy.allowed_imports || [],
      maxModuleSize: activePolicy.max_module_size,
    });
    if (!validation.is_valid) blockedReason = validation.errors.concat(validation.findings.map((finding) => finding.message)).join(' ');
  }

  if (!blockedReason && activePolicy.require_signature) {
    const [keyRows] = fn.signer_key_id
      ? await pool.execute('SELECT public_key FROM signing_keys WHERE id = ?', [fn.signer_key_id])
      : [[]];
    const signatureValid = fn.signature_ed25519 && keyRows.length
      && verifyModuleSignature(keyRows[0].public_key, bytes, fn.signature_ed25519);
    if (!signatureValid) blockedReason = 'Execution policy requires a valid module signature.';
  }

  const now = new Date();
  let workerResult;
  let status;
  let outputJson;
  if (blockedReason) {
    status = 'blocked';
    outputJson = { ok: false, error: blockedReason };
    workerResult = {
      ok: false, error: blockedReason, exit_reason: 'blocked', duration_ms: 0,
      fuel_consumed: null, memory_bytes: 0, stdout: '', stderr: '',
    };
    if (integrityStatus === 'tamper_detected') {
      await addSecurityEvent(req.user.id, 'integrity_violation', 'critical', blockedReason, {}, fn.id);
    }
  } else {
    workerResult = await executeInWorker(bytes, data.function_name, data.args, activePolicy);
    status = workerResult.ok
      ? 'success'
      : workerResult.exit_reason === 'timeout'
        ? 'timeout'
        : workerResult.exit_reason === 'fuel_exhausted'
          ? 'fuel_exhausted'
          : workerResult.exit_reason.startsWith('trap')
            ? 'trapped'
            : 'failed';
    outputJson = { ok: workerResult.ok, ...(workerResult.ok ? { result: workerResult.result } : { error: workerResult.error }) };
    if (!workerResult.ok) {
      await addSecurityEvent(req.user.id, 'execution_failure', 'warning', workerResult.error, {
        exit_reason: workerResult.exit_reason,
      }, fn.id);
    }
  }

  const [result] = await pool.execute(
    `INSERT INTO executions
      (function_id, user_id, policy_id, execution_status, input_json, output_json, stdout, stderr,
       error_message, integrity_status, execution_time_ms, fuel_consumed, memory_consumed_bytes,
       memory_limit_bytes, worker_exit_reason, completed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      fn.id, req.user.id, activePolicy.id, status, JSON.stringify(inputJson), JSON.stringify(outputJson),
      workerResult.stdout || '', workerResult.stderr || '', workerResult.ok ? null : workerResult.error,
      integrityStatus, workerResult.duration_ms, workerResult.fuel_consumed,
      workerResult.memory_bytes, activePolicy.max_memory_bytes, workerResult.exit_reason, now,
    ],
  );
  const [savedRows] = await pool.execute('SELECT * FROM executions WHERE id = ?', [result.insertId]);
  await appendAuditLog(pool, req.user.username, 'execution_completed', 'execution', result.insertId, {
    function_id: fn.id, execution_status: status, worker_exit_reason: workerResult.exit_reason,
  });
  res.json(executionOut(savedRows[0]));
}));

app.get('/api/executions', authenticate, asyncRoute(async (req, res) => {
  const [rows] = req.user.role === 'admin'
    ? await pool.query('SELECT * FROM executions ORDER BY created_at DESC LIMIT 100')
    : await pool.execute('SELECT * FROM executions WHERE user_id = ? ORDER BY created_at DESC LIMIT 100', [req.user.id]);
  res.json(rows.map(executionOut));
}));

app.get('/api/policies', authenticate, asyncRoute(async (req, res) => {
  const [rows] = req.user.role === 'admin'
    ? await pool.query('SELECT * FROM execution_policies ORDER BY id')
    : await pool.query('SELECT * FROM execution_policies WHERE is_enabled = 1 ORDER BY id');
  res.json(rows.map(policyOut));
}));

app.post('/api/policies', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const policy = schemas.policyCreate(req.body);
  try {
    const [result] = await pool.execute(
      `INSERT INTO execution_policies
        (name, description, max_module_size, max_fuel, max_memory_bytes, timeout_ms,
         max_input_bytes, max_output_bytes, allowed_imports, require_signature, is_enabled)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        policy.name, policy.description, policy.max_module_size, policy.max_fuel,
        policy.max_memory_bytes, policy.timeout_ms, policy.max_input_bytes,
        policy.max_output_bytes, JSON.stringify(policy.allowed_imports),
        policy.require_signature, policy.is_enabled,
      ],
    );
    const [rows] = await pool.execute('SELECT * FROM execution_policies WHERE id = ?', [result.insertId]);
    res.status(201).json(policyOut(rows[0]));
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') throw httpError(400, 'A policy with this name already exists');
    throw error;
  }
}));

app.get('/api/audit', authenticate, asyncRoute(async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM audit_log ORDER BY sequence_number DESC LIMIT 100');
  res.json(rows.map(auditOut));
}));

app.post('/api/audit/verify', authenticate, asyncRoute(async (req, res) => {
  res.json(await verifyAuditChain(pool));
}));

app.post('/api/audit/simulate-tamper', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const [[last]] = await pool.query('SELECT id, details_json FROM audit_log ORDER BY sequence_number DESC LIMIT 1');
  if (!last) return res.json({ message: 'Audit chain is empty; nothing to tamper with.' });
  const details = parseJson(last.details_json, {});
  details.tampered = true;
  await pool.execute('UPDATE audit_log SET details_json = ? WHERE id = ?', [JSON.stringify(details), last.id]);
  res.json({ message: 'Audit chain tampered successfully. Verify the chain to identify the modified block.' });
}));

app.post('/api/audit/restore-chain', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const connection = await pool.getConnection();
  let auditLockAcquired = false;
  try {
    const [lockRows] = await connection.query("SELECT GET_LOCK('wasm_audit_chain', 10) AS acquired");
    if (Number(lockRows[0]?.acquired) !== 1) throw new Error('Unable to acquire the audit-chain write lock');
    auditLockAcquired = true;
    await connection.beginTransaction();
    await connection.query('SELECT id FROM audit_log ORDER BY sequence_number FOR UPDATE');
    const [entries] = await connection.query('SELECT * FROM audit_log ORDER BY sequence_number ASC');
    let previousHash = GENESIS_PREV_HASH;
    for (const entry of entries) {
      const details = parseJson(entry.details_json, {});
      const payloadHash = computeSha256(canonicalizeJson(details || {}));
      const updated = {
        ...entry,
        previous_hash: previousHash,
        payload_hash: payloadHash,
      };
      const entryHash = computeAuditEntryHash(updated);
      await connection.execute(
        'UPDATE audit_log SET details_json = ?, payload_hash = ?, previous_hash = ?, entry_hash = ? WHERE id = ?',
        [JSON.stringify(details), payloadHash, previousHash, entryHash, entry.id],
      );
      previousHash = entryHash;
    }
    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    if (auditLockAcquired) await connection.query("SELECT RELEASE_LOCK('wasm_audit_chain')");
    connection.release();
  }
  res.json({ message: 'Audit chain has been re-sealed and restored.' });
}));

app.get('/api/security-events', authenticate, asyncRoute(async (req, res) => {
  const [rows] = req.user.role === 'admin'
    ? await pool.query('SELECT * FROM security_events ORDER BY created_at DESC LIMIT 50')
    : await pool.execute('SELECT * FROM security_events WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.user.id]);
  res.json(rows.map(eventOut));
}));

app.get('/api/dashboard', authenticate, asyncRoute(async (req, res) => {
  const ownOnly = req.user.role !== 'admin';
  const userClause = ownOnly ? ' WHERE user_id = ?' : '';
  const [executionRows] = ownOnly
    ? await pool.execute(`SELECT * FROM executions${userClause} ORDER BY created_at DESC`, [req.user.id])
    : await pool.query('SELECT * FROM executions ORDER BY created_at DESC');
  const [functionRows] = ownOnly
    ? await pool.execute('SELECT * FROM functions WHERE owner_id IN (?, ?) ORDER BY created_at DESC', [req.user.id, adminUserId])
    : await pool.query('SELECT * FROM functions ORDER BY created_at DESC');
  const [eventRows] = ownOnly
    ? await pool.execute('SELECT * FROM security_events WHERE user_id = ? ORDER BY created_at DESC LIMIT 8', [req.user.id])
    : await pool.query('SELECT * FROM security_events ORDER BY created_at DESC LIMIT 8');

  const executions = executionRows.map(executionOut);
  const success = executions.filter((row) => row.execution_status === 'success').length;
  const failed = executions.filter((row) => ['failed', 'trapped'].includes(row.execution_status)).length;
  const blocked = executions.filter((row) => row.execution_status === 'blocked').length;
  const timeouts = executions.filter((row) => row.execution_status === 'timeout').length;
  const durations = executions.map((row) => row.execution_time_ms).filter(Number.isFinite);
  const fuels = executions.map((row) => row.fuel_consumed).filter(Number.isFinite);
  const statusGroups = [
    { name: 'Success', value: success },
    { name: 'Failed', value: failed },
    { name: 'Blocked', value: blocked },
    { name: 'Timeout', value: timeouts },
  ];
  const [allExecutionRows] = ownOnly
    ? await pool.execute('SELECT function_id, execution_status, created_at FROM executions WHERE user_id = ? ORDER BY created_at DESC', [req.user.id])
    : await pool.query('SELECT function_id, execution_status, created_at FROM executions ORDER BY created_at DESC');
  const allActivity = new Map();
  for (const row of allExecutionRows) {
    const day = String(row.created_at).slice(0, 10);
    allActivity.set(day, (allActivity.get(day) || 0) + 1);
  }
  const recentFunctions = functionRows.slice(0, 6).map(functionOut);
  const recentExecutions = executions.slice(0, 6);

  res.json({
    total_functions: functionRows.length,
    total_executions: executions.length,
    successful_executions: success,
    failed_executions: failed,
    blocked_executions: blocked,
    timeout_executions: timeouts,
    avg_duration_ms: durations.length ? Number((durations.reduce((sum, value) => sum + value, 0) / durations.length).toFixed(2)) : 0,
    avg_fuel_consumed: fuels.length ? Number((fuels.reduce((sum, value) => sum + value, 0) / fuels.length).toFixed(1)) : 0,
    integrity_failures: executions.filter((row) => row.integrity_status === 'tamper_detected').length,
    worker_health: await getWorkerHealth(),
    recent_events: eventRows.map(eventOut),
    function_activity: [...allActivity.entries()].sort(([left], [right]) => right.localeCompare(left)).slice(0, 7)
      .map(([name, count]) => ({ name, executions: count })),
    execution_status_counts: statusGroups,
    recent_functions: recentFunctions,
    recent_executions: recentExecutions,
  });
}));

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error.name === 'SchemaValidationError') {
    return res.status(422).json({ detail: error.issues });
  }
  if (error instanceof multer.MulterError) {
    const message = error.code === 'LIMIT_FILE_SIZE' ? 'Uploaded file exceeds the configured size limit' : error.message;
    return res.status(400).json({ detail: message });
  }
  const status = error.status || 500;
  if (status >= 500) console.error('API request failed:', error);
  return res.status(status).json({ detail: status === 500 ? 'Internal server error' : error.message });
});

async function start() {
  await initialize();
  return app.listen(config.PORT, '0.0.0.0', () => {
    console.log(`JavaScript WebAssembly backend listening on port ${config.PORT}`);
    if (!config.SECRET_KEY) console.warn('SECRET_KEY is unset; JWTs will not survive a process restart.');
  });
}

if (require.main === module) {
  start().catch((error) => {
    console.error('Backend startup failed:', error);
    pool.end()
      .catch((closeError) => console.error('Failed to close database pool:', closeError))
      .finally(() => {
        process.exitCode = 1;
      });
  });
}

module.exports = { app, initialize, start };
