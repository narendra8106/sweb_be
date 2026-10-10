const { parentPort, workerData } = require('node:worker_threads');

function jsonSafe(value) {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(jsonSafe);
  return value;
}

function exitReason(error) {
  const message = String(error && error.message || error);
  if (/divide by zero/i.test(message)) return 'trap_divide_by_zero';
  if (/unreachable/i.test(message)) return 'trap_unreachable';
  if (/memory|out of bounds/i.test(message)) return 'out_of_bounds_memory';
  return 'trap_runtime';
}

try {
  const module = new WebAssembly.Module(new Uint8Array(workerData.bytes));
  const imports = WebAssembly.Module.imports(module);
  if (imports.length) {
    throw new Error(`Unsupported WebAssembly imports: ${imports.map(({ module: mod, name }) => `${mod}.${name}`).join(', ')}`);
  }

  const instance = new WebAssembly.Instance(module);
  const exported = instance.exports[workerData.functionName];
  if (typeof exported !== 'function') {
    throw new Error(`Exported function '${workerData.functionName}' was not found.`);
  }

  const result = exported(...workerData.args);
  const memory = Object.values(instance.exports).find((item) => item instanceof WebAssembly.Memory);
  const memoryBytes = memory ? memory.buffer.byteLength : 0;
  parentPort.postMessage({
    ok: true,
    result: jsonSafe(result),
    exit_reason: 'completed',
    fuel_consumed: null,
    memory_bytes: memoryBytes,
    stdout: '',
    stderr: '',
  });
} catch (error) {
  parentPort.postMessage({
    ok: false,
    error: String(error && error.message || error),
    exit_reason: exitReason(error),
    fuel_consumed: null,
    memory_bytes: 0,
    stdout: '',
    stderr: '',
  });
}
