const test = require('node:test');
const assert = require('node:assert/strict');
const {
  computeSha256,
  generateEd25519Keypair,
  signModuleBytes,
  verifyIntegrityDigest,
  verifyModuleSignature,
} = require('../src/services/cryptoEngine');
const { schemas, SchemaValidationError } = require('../src/schemas');
const { compileWat, templates, validateModule } = require('../src/services/wasmValidator');
const { executeInWorker } = require('../src/services/workerManager');
const { app } = require('../src/server');

test('JavaScript request schemas enforce required field constraints and defaults', () => {
  assert.equal(schemas.userCreate({ username: 'abc', email: 'x@y.z', password: 'password' }).username, 'abc');
  assert.deepEqual(schemas.executionRequest({ module_id: 1 }).args, []);
  assert.throws(
    () => schemas.userCreate({ username: 'ab', email: 'x@y.z', password: 'short' }),
    SchemaValidationError,
  );
});

test('SHA-256 digest checks are strict and detect modified bytes', () => {
  const bytes = Buffer.from('wasm-file');
  const digest = computeSha256(bytes);
  assert.equal(verifyIntegrityDigest(digest, bytes), true);
  assert.equal(verifyIntegrityDigest(digest, Buffer.from('tampered')), false);
  assert.equal(verifyIntegrityDigest('bad', bytes), false);
});

test('Ed25519 signatures verify against the raw public key and reject tampering', () => {
  const pair = generateEd25519Keypair();
  const bytes = Buffer.from('wasm-module');
  const signature = signModuleBytes(pair.private_key_pem, bytes);
  assert.equal(verifyModuleSignature(pair.public_key_hex, bytes, signature), true);
  assert.equal(verifyModuleSignature(pair.public_key_hex, Buffer.from('changed'), signature), false);
});

test('WAT compiles, validates, and reports exports', async () => {
  const bytes = await compileWat('(module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))');
  const report = await validateModule(bytes);
  assert.equal(report.is_valid, true);
  assert.equal(report.sha256_hash, computeSha256(bytes));
  assert.ok(report.exports.some((entry) => entry.name === 'add'));
});

test('all seeded WAT templates compile to valid WebAssembly modules', async () => {
  for (const template of templates) {
    const bytes = await compileWat(template.wat);
    const report = await validateModule(bytes, { allowedImports: ['wasi_snapshot_preview1.sock_send'] });
    assert.equal(report.is_valid, true, `${template.id}: ${report.errors.join('; ')}`);
  }
});

test('validator rejects malformed bytes and unauthorized imports', async () => {
  const invalid = await validateModule(Buffer.from('NOTWASM'));
  assert.equal(invalid.is_valid, false);
  assert.match(invalid.errors[0], /magic header/i);

  const imported = await compileWat('(module (import "env" "log" (func)) (func (export "run")))');
  const report = await validateModule(imported, { allowedImports: [] });
  assert.equal(report.is_valid, false);
  assert.ok(report.findings.some((finding) => /not allowed/i.test(finding.message)));
});

test('worker executes WebAssembly exports off the request thread', async () => {
  const bytes = await compileWat('(module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))');
  const result = await executeInWorker(bytes, 'add', [10, 20], { timeout_ms: 1000 });
  assert.equal(result.ok, true);
  assert.equal(result.result, 30);
  assert.equal(result.exit_reason, 'completed');
  assert.equal(result.fuel_consumed, null);
});

test('worker timeouts contain an infinite loop', async () => {
  const bytes = await compileWat('(module (func (export "loop") (loop $again br $again)))');
  const result = await executeInWorker(bytes, 'loop', [], { timeout_ms: 100 });
  assert.equal(result.ok, false);
  assert.equal(result.exit_reason, 'timeout');
});

test('public health and template API routes are available without a database session', async (context) => {
  const server = app.listen(0);
  context.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}/api`;

  const health = await fetch(`${baseUrl}/health`);
  assert.equal(health.status, 200);
  assert.equal((await health.json()).status, 'healthy');

  const workerHealthResponse = await fetch(`${baseUrl}/health/worker`);
  assert.equal(workerHealthResponse.status, 200);
  assert.equal((await workerHealthResponse.json()).status, 'healthy');

  const templateResponse = await fetch(`${baseUrl}/templates`);
  assert.equal(templateResponse.status, 200);
  assert.equal((await templateResponse.json()).length, 8);
});
