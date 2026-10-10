class SchemaValidationError extends Error {
  constructor(issues) {
    super('Request validation failed');
    this.name = 'SchemaValidationError';
    this.issues = issues;
  }
}

function validate(body, rules) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new SchemaValidationError([{ loc: ['body'], msg: 'Input should be an object', type: 'model_type' }]);
  }

  const issues = [];
  const result = { ...body };

  for (const [key, rule] of Object.entries(rules)) {
    let value = result[key];
    if (value === undefined && Object.prototype.hasOwnProperty.call(rule, 'default')) {
      value = typeof rule.default === 'function' ? rule.default() : rule.default;
      result[key] = value;
    }

    if (value === undefined || value === null) {
      if (rule.required && value === undefined) {
        issues.push({ loc: ['body', key], msg: 'Field required', type: 'missing' });
      } else if (value === null && !rule.nullable) {
        issues.push({ loc: ['body', key], msg: 'Input should not be null', type: 'none_required' });
      }
      continue;
    }

    if (rule.type === 'string') {
      if (typeof value !== 'string') {
        issues.push({ loc: ['body', key], msg: 'Input should be a valid string', type: 'string_type' });
        continue;
      }
      if (rule.min !== undefined && value.length < rule.min) {
        issues.push({ loc: ['body', key], msg: `String should have at least ${rule.min} characters`, type: 'string_too_short' });
      }
      if (rule.max !== undefined && value.length > rule.max) {
        issues.push({ loc: ['body', key], msg: `String should have at most ${rule.max} characters`, type: 'string_too_long' });
      }
    } else if (rule.type === 'number') {
      if (!Number.isInteger(value)) {
        issues.push({ loc: ['body', key], msg: 'Input should be a valid integer', type: 'int_type' });
      }
    } else if (rule.type === 'boolean' && typeof value !== 'boolean') {
      issues.push({ loc: ['body', key], msg: 'Input should be a valid boolean', type: 'bool_type' });
    } else if (rule.type === 'array' && !Array.isArray(value)) {
      issues.push({ loc: ['body', key], msg: 'Input should be a valid list', type: 'list_type' });
    } else if (rule.type === 'object' && (typeof value !== 'object' || Array.isArray(value))) {
      issues.push({ loc: ['body', key], msg: 'Input should be a valid dictionary', type: 'dict_type' });
    }
  }

  if (issues.length) throw new SchemaValidationError(issues);
  return result;
}

const nullableId = { type: 'number', nullable: true };
const policyRules = {
  name: { type: 'string', required: true, max: 80 },
  description: { type: 'string', default: '' },
  max_module_size: { type: 'number', default: 1048576 },
  max_fuel: { type: 'number', default: 100000 },
  max_memory_bytes: { type: 'number', default: 33554432 },
  timeout_ms: { type: 'number', default: 5000 },
  max_input_bytes: { type: 'number', default: 4096 },
  max_output_bytes: { type: 'number', default: 16384 },
  allowed_imports: { type: 'array', default: () => [] },
  require_signature: { type: 'boolean', default: false },
  is_enabled: { type: 'boolean', default: true },
};

const schemas = {
  userCreate(body) {
    return validate(body, {
      username: { type: 'string', required: true, min: 3, max: 80 },
      email: { type: 'string', required: true, min: 5, max: 120 },
      password: { type: 'string', required: true, min: 8, max: 128 },
    });
  },
  userLogin(body) {
    return validate(body, {
      username: { type: 'string', required: true },
      password: { type: 'string', required: true },
    });
  },
  signingKeyCreate(body) {
    return validate(body, { key_name: { type: 'string', required: true, min: 3, max: 120 } });
  },
  functionCreate(body) {
    return validate(body, {
      name: { type: 'string', required: true, min: 1, max: 120 },
      description: { type: 'string', default: '' },
      source_wat: { type: 'string', nullable: true },
    });
  },
  validationRequest(body) {
    return validate(body, {
      source_wat: { type: 'string', required: true },
      policy_id: nullableId,
    });
  },
  signFunctionRequest(body) {
    return validate(body, { key_id: { type: 'number', required: true } });
  },
  policyCreate(body) {
    return validate(body, policyRules);
  },
  executionRequest(body) {
    return validate(body, {
      module_id: { type: 'number', required: true },
      function_name: { type: 'string', default: 'add' },
      args: { type: 'array', default: () => [] },
      policy_id: nullableId,
    });
  },
};

module.exports = { SchemaValidationError, schemas };
