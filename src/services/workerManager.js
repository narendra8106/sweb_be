const path = require('path');
const { Worker } = require('node:worker_threads');
const { performance } = require('node:perf_hooks');

function executeInWorker(bytes, functionName, args, policy) {
  const startedAt = performance.now();
  const worker = new Worker(path.join(__dirname, 'wasmWorker.js'), {
    workerData: { bytes: Array.from(bytes), functionName, args },
    resourceLimits: {
      maxOldGenerationSizeMb: 128,
      maxYoungGenerationSizeMb: 32,
      stackSizeMb: 4,
    },
  });
  const timeoutMs = Math.max(1, Number(policy.timeout_ms) || 5000);

  return new Promise((resolve) => {
    let settled = false;
    const finish = async (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      await worker.terminate();
      resolve({
        ...result,
        duration_ms: Number((performance.now() - startedAt).toFixed(2)),
        fuel_consumed: null,
      });
    };

    const timer = setTimeout(() => {
      finish({
        ok: false,
        error: `Execution exceeded the ${timeoutMs} ms wall-clock limit.`,
        exit_reason: 'timeout',
        memory_bytes: 0,
        stdout: '',
        stderr: '',
      });
    }, timeoutMs);

    worker.once('message', (result) => finish(result));
    worker.once('error', (error) => finish({
      ok: false,
      error: `Worker execution failed: ${error.message}`,
      exit_reason: 'worker_spawn_failure',
      memory_bytes: 0,
      stdout: '',
      stderr: '',
    }));
    worker.once('exit', (code) => {
      if (!settled) {
        finish({
          ok: false,
          error: `Worker exited without a result (exit code ${code}).`,
          exit_reason: 'empty_worker_output',
          memory_bytes: 0,
          stdout: '',
          stderr: '',
        });
      }
    });
  });
}

async function getWorkerHealth() {
  const startedAt = performance.now();
  const worker = new Worker(
    "require('node:worker_threads').parentPort.postMessage('ready')",
    { eval: true },
  );
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Worker health probe timed out')), 1000);
      worker.once('message', (message) => {
        clearTimeout(timer);
        if (message !== 'ready') reject(new Error('Worker health probe returned an invalid response'));
        else resolve();
      });
      worker.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  } finally {
    await worker.terminate();
  }
  return {
    status: 'healthy',
    worker_mode: 'node_worker_thread',
    runtime: 'WebAssembly JavaScript API',
    runtime_version: process.versions.v8,
    python_version: 'not_applicable',
    probe_latency_ms: Number((performance.now() - startedAt).toFixed(2)),
    features: {
      wall_clock_timeout: true,
      process_isolation: false,
      instruction_fuel_metering: false,
      linear_memory_limit: false,
      ed25519_signatures: true,
    },
  };
}

module.exports = { executeInWorker, getWorkerHealth };
