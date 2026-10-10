let wabtInstance;

const templates = [
  {
    id: 'add', name: 'Math: Add Numbers', category: 'computation',
    description: 'Adds two signed 32-bit integers.', entry_point: 'add', default_args: [15, 35],
    wat: '(module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))',
  },
  {
    id: 'fibonacci', name: 'Algorithm: Fibonacci', category: 'computation',
    description: 'Calculates a Fibonacci number recursively.', entry_point: 'fibonacci', default_args: [10],
    wat: '(module (func $fib (export "fibonacci") (param $n i32) (result i32) local.get $n i32.const 2 i32.lt_s if (result i32) local.get $n else local.get $n i32.const 1 i32.sub call $fib local.get $n i32.const 2 i32.sub call $fib i32.add end))',
  },
  {
    id: 'prime_sieve', name: 'Data: Prime Sieve Check', category: 'computation',
    description: 'Checks whether an integer is prime.', entry_point: 'is_prime', default_args: [97],
    wat: '(module (func (export "is_prime") (param $n i32) (result i32) (local $i i32) local.get $n i32.const 2 i32.lt_s if i32.const 0 return end i32.const 2 local.set $i block $done loop $check local.get $i local.get $i i32.mul local.get $n i32.gt_u br_if $done local.get $n local.get $i i32.rem_u i32.eqz if i32.const 0 return end local.get $i i32.const 1 i32.add local.set $i br $check end end i32.const 1))',
  },
  {
    id: 'infinite_loop', name: 'Attack: Infinite Loop (CPU Bomb)', category: 'attack',
    description: 'An infinite loop used to demonstrate execution timeout containment.', entry_point: 'loop_forever', default_args: [],
    wat: '(module (func (export "loop_forever") (loop $again br $again)))',
  },
  {
    id: 'memory_bomb', name: 'Attack: Memory Allocation Bomb', category: 'attack',
    description: 'Attempts to grow linear memory beyond its configured limit.', entry_point: 'grow_memory', default_args: [1000],
    wat: '(module (memory (export "memory") 1 16) (func (export "grow_memory") (param i32) (result i32) local.get 0 memory.grow))',
  },
  {
    id: 'trap_div_zero', name: 'Attack: Division by Zero Trap', category: 'attack',
    description: 'Triggers an integer divide-by-zero trap.', entry_point: 'divide_by_zero', default_args: [100, 0],
    wat: '(module (func (export "divide_by_zero") (param i32 i32) (result i32) local.get 0 local.get 1 i32.div_s))',
  },
  {
    id: 'trap_unreachable', name: 'Attack: Unreachable Opcode Trap', category: 'attack',
    description: 'Triggers the WebAssembly unreachable instruction.', entry_point: 'trigger_unreachable', default_args: [],
    wat: '(module (func (export "trigger_unreachable") unreachable))',
  },
  {
    id: 'unauthorized_syscall', name: 'Attack: Unauthorized Socket Syscall', category: 'attack',
    description: 'Attempts to import a prohibited WASI socket capability.', entry_point: 'send_packet', default_args: [],
    wat: '(module (import "wasi_snapshot_preview1" "sock_send" (func $sock_send (param i32) (result i32))) (func (export "send_packet") (result i32) i32.const 0 call $sock_send))',
  },
];

async function getWabt() {
  if (!wabtInstance) wabtInstance = require('wabt')();
  return wabtInstance;
}

async function compileWat(sourceWat) {
  const wabt = await getWabt();
  const module = wabt.parseWat('module.wat', sourceWat, {
    bulk_memory: true,
    reference_types: true,
    multi_value: true,
  });
  try {
    module.validate();
    return Buffer.from(module.toBinary({}).buffer);
  } finally {
    module.destroy();
  }
}

function isImportAllowed(entry, allowedImports) {
  return allowedImports.some((pattern) => {
    if (pattern.endsWith('.*')) return entry.module === pattern.slice(0, -2);
    return entry.module === pattern || `${entry.module}.${entry.name}` === pattern;
  });
}

async function validateModule(bytes, options = {}) {
  const report = {
    is_valid: false,
    sha256_hash: null,
    module_size: bytes.length,
    imports: [],
    exports: [],
    has_memory: false,
    risk_level: 'LOW',
    risk_score: 0,
    findings: [],
    errors: [],
  };

  if (bytes.length < 8 || bytes[0] !== 0 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
    report.errors.push('Invalid WebAssembly binary magic header.');
    report.risk_level = 'HIGH';
    report.risk_score = 100;
    return report;
  }

  if (options.maxModuleSize && bytes.length > options.maxModuleSize) {
    report.errors.push(`Module size ${bytes.length} exceeds policy limit ${options.maxModuleSize}.`);
  }

  try {
    const module = await WebAssembly.compile(bytes);
    report.imports = WebAssembly.Module.imports(module).map(({ module: mod, name, kind }) => ({ module: mod, name, kind }));
    report.exports = WebAssembly.Module.exports(module).map(({ name, kind }) => ({ name, kind }));
    report.has_memory = report.exports.some(({ kind, name }) => kind === 'memory' || name === 'memory');
    report.sha256_hash = require('crypto').createHash('sha256').update(bytes).digest('hex');

    const allowedImports = options.allowedImports || [];
    for (const entry of report.imports) {
      if (!isImportAllowed(entry, allowedImports)) {
        report.risk_score += 35;
        report.findings.push({
          severity: 'HIGH',
          message: `Import '${entry.module}.${entry.name}' is not allowed by the active policy.`,
        });
      }
      if (/wasi|socket|sock|network/i.test(`${entry.module}.${entry.name}`)) {
        report.risk_score += 25;
        report.findings.push({
          severity: 'HIGH',
          message: `Potentially dangerous capability import detected: '${entry.module}.${entry.name}'.`,
        });
      }
    }

    if (report.has_memory) {
      report.risk_score += 5;
      report.findings.push({ severity: 'LOW', message: 'Module exports linear memory.' });
    }

    report.risk_score = Math.min(100, report.risk_score);
    report.risk_level = report.risk_score >= 70 ? 'HIGH' : report.risk_score >= 30 ? 'MEDIUM' : 'LOW';
    if (report.errors.length) report.risk_level = 'HIGH';
    report.is_valid = report.errors.length === 0 && report.imports.every((entry) => isImportAllowed(entry, allowedImports));
  } catch (error) {
    report.errors.push(`Invalid WebAssembly module: ${error.message}`);
    report.risk_level = 'HIGH';
    report.risk_score = 100;
  }

  return report;
}

function templateMetadata(template) {
  return {
    entry_point: template.entry_point,
    default_args: template.default_args,
    category: template.category,
    imports: [],
    exports: [{ name: template.entry_point, kind: 'function' }],
  };
}

module.exports = { compileWat, validateModule, templates, templateMetadata };
