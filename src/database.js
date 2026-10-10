const mysql = require('mysql2/promise');
const config = require('./config');

function createPool() {
  const poolOptions = {
    waitForConnections: true,
    connectionLimit: Number.parseInt(process.env.DB_POOL_SIZE || '10', 10),
    queueLimit: 0,
    decimalNumbers: true,
    dateStrings: true,
  };

  if (config.DATABASE_URL) {
    const url = new URL(config.DATABASE_URL);
    if (url.protocol !== 'mysql:' && url.protocol !== 'mysql2:') {
      throw new Error('DATABASE_URL must use the mysql:// scheme');
    }
    return mysql.createPool({
      ...poolOptions,
      host: url.hostname,
      port: Number(url.port || 3306),
      database: decodeURIComponent(url.pathname.replace(/^\//, '')),
      user: decodeURIComponent(url.username),
      password: decodeURIComponent(url.password),
    });
  }

  return mysql.createPool({
    ...poolOptions,
    host: config.DB_HOST,
    port: config.DB_PORT,
    database: config.DB_NAME,
    user: config.DB_USER,
    password: config.DB_PASSWORD,
  });
}

const pool = createPool();

const compatibilityColumns = {
  execution_policies: {
    name: 'VARCHAR(80) NULL',
    description: 'TEXT NULL',
    max_module_size: 'INT NULL DEFAULT 1048576',
    max_fuel: 'INT NULL DEFAULT 100000',
    max_memory_bytes: 'BIGINT NULL DEFAULT 33554432',
    timeout_ms: 'INT NULL DEFAULT 5000',
    max_input_bytes: 'INT NULL DEFAULT 4096',
    max_output_bytes: 'INT NULL DEFAULT 16384',
    allowed_imports: 'JSON NULL',
    require_signature: 'TINYINT(1) NULL DEFAULT 0',
    is_enabled: 'TINYINT(1) NULL DEFAULT 1',
    updated_at: 'DATETIME NULL',
  },
  executions: {
    function_id: 'INT NULL',
    user_id: 'INT NULL',
    policy_id: 'INT NULL',
    execution_status: "VARCHAR(32) NULL DEFAULT 'pending'",
    input_json: 'JSON NULL',
    output_json: 'JSON NULL',
    stdout: 'MEDIUMTEXT NULL',
    stderr: 'MEDIUMTEXT NULL',
    error_message: 'TEXT NULL',
    integrity_status: "VARCHAR(32) NULL DEFAULT 'verified'",
    fuel_consumed: 'BIGINT NULL DEFAULT 0',
    memory_consumed_bytes: 'BIGINT NULL DEFAULT 0',
    memory_limit_bytes: 'BIGINT NULL DEFAULT 0',
    worker_exit_reason: "VARCHAR(80) NULL DEFAULT ''",
    completed_at: 'DATETIME NULL',
  },
};

async function migrateLegacyTables() {
  for (const [table, columns] of Object.entries(compatibilityColumns)) {
    const [existingColumns] = await pool.execute(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?`,
      [table],
    );
    const existingNames = new Set(existingColumns.map((column) => column.COLUMN_NAME));

    for (const [column, definition] of Object.entries(columns)) {
      if (existingNames.has(column)) continue;
      await pool.query(`ALTER TABLE \`${table}\` ADD COLUMN \`${column}\` ${definition}`);
    }
  }

  const [policyColumns] = await pool.execute(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'execution_policies'`,
  );
  const existingPolicyColumns = new Set(policyColumns.map((column) => column.COLUMN_NAME));
  if (existingPolicyColumns.has('policy_name')) {
    await pool.query(
      'UPDATE execution_policies SET name = policy_name WHERE name IS NULL AND policy_name IS NOT NULL',
    );
  }

  const [executionColumns] = await pool.execute(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'executions'`,
  );
  const existingExecutionColumns = new Set(executionColumns.map((column) => column.COLUMN_NAME));
  if (existingExecutionColumns.has('status')) {
    await pool.query(
      `UPDATE executions SET execution_status = status
       WHERE (execution_status IS NULL OR execution_status = 'pending') AND status IS NOT NULL`,
    );
  }
  if (existingExecutionColumns.has('input_json')) {
    await pool.query(
      'UPDATE executions SET input_json = JSON_OBJECT() WHERE input_json IS NULL',
    );
  }
  await pool.query(
    'UPDATE execution_policies SET allowed_imports = JSON_ARRAY() WHERE allowed_imports IS NULL',
  );

  return {
    legacyPolicyName: existingPolicyColumns.has('policy_name'),
    legacyPolicyJson: existingPolicyColumns.has('policy_json'),
  };
}

async function initSchema() {
  const definitions = [
    `CREATE TABLE IF NOT EXISTS users (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(80) NOT NULL UNIQUE,
      email VARCHAR(120) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      role VARCHAR(32) NOT NULL DEFAULT 'developer',
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB`,
    `CREATE TABLE IF NOT EXISTS signing_keys (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      owner_id INT NOT NULL,
      key_name VARCHAR(120) NOT NULL,
      public_key TEXT NOT NULL,
      private_key_pem TEXT,
      algorithm VARCHAR(32) NOT NULL DEFAULT 'ed25519',
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      revoked_at DATETIME NULL,
      CONSTRAINT fk_signing_keys_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB`,
    `CREATE TABLE IF NOT EXISTS functions (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      owner_id INT NOT NULL,
      signer_key_id INT NULL,
      name VARCHAR(120) NOT NULL,
      description TEXT,
      module_filename VARCHAR(255) NOT NULL,
      storage_path VARCHAR(1024) NOT NULL,
      sha256_hash CHAR(64) NOT NULL,
      signature_ed25519 TEXT,
      signature_status VARCHAR(32) NOT NULL DEFAULT 'not_required',
      source_wat MEDIUMTEXT,
      abi_metadata JSON NULL,
      status VARCHAR(32) NOT NULL DEFAULT 'active',
      module_size INT NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_functions_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
      CONSTRAINT fk_functions_signer FOREIGN KEY (signer_key_id) REFERENCES signing_keys(id) ON DELETE SET NULL,
      INDEX idx_functions_owner (owner_id),
      INDEX idx_functions_name (name)
    ) ENGINE=InnoDB`,
    `CREATE TABLE IF NOT EXISTS execution_policies (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(80) NOT NULL UNIQUE,
      description TEXT NOT NULL,
      max_module_size INT NOT NULL DEFAULT 1048576,
      max_fuel INT NOT NULL DEFAULT 100000,
      max_memory_bytes BIGINT NOT NULL DEFAULT 33554432,
      timeout_ms INT NOT NULL DEFAULT 5000,
      max_input_bytes INT NOT NULL DEFAULT 4096,
      max_output_bytes INT NOT NULL DEFAULT 16384,
      allowed_imports JSON NOT NULL,
      require_signature TINYINT(1) NOT NULL DEFAULT 0,
      is_enabled TINYINT(1) NOT NULL DEFAULT 1,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB`,
    `CREATE TABLE IF NOT EXISTS executions (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      function_id INT NOT NULL,
      user_id INT NOT NULL,
      policy_id INT NULL,
      execution_status VARCHAR(32) NOT NULL DEFAULT 'pending',
      input_json JSON NULL,
      output_json JSON NULL,
      stdout MEDIUMTEXT,
      stderr MEDIUMTEXT,
      error_message TEXT,
      integrity_status VARCHAR(32) NOT NULL DEFAULT 'verified',
      execution_time_ms DOUBLE NULL DEFAULT 0,
      fuel_consumed BIGINT NULL DEFAULT 0,
      memory_consumed_bytes BIGINT NULL DEFAULT 0,
      memory_limit_bytes BIGINT NULL DEFAULT 0,
      worker_exit_reason VARCHAR(80) NULL DEFAULT '',
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME NULL,
      CONSTRAINT fk_executions_function FOREIGN KEY (function_id) REFERENCES functions(id) ON DELETE CASCADE,
      CONSTRAINT fk_executions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      CONSTRAINT fk_executions_policy FOREIGN KEY (policy_id) REFERENCES execution_policies(id) ON DELETE SET NULL,
      INDEX idx_executions_user_created (user_id, created_at),
      INDEX idx_executions_function (function_id)
    ) ENGINE=InnoDB`,
    `CREATE TABLE IF NOT EXISTS security_events (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      function_id INT NULL,
      execution_id INT NULL,
      event_type VARCHAR(80) NOT NULL,
      severity VARCHAR(32) NOT NULL DEFAULT 'info',
      description TEXT NOT NULL,
      metadata_json JSON NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_events_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
      CONSTRAINT fk_events_function FOREIGN KEY (function_id) REFERENCES functions(id) ON DELETE SET NULL,
      CONSTRAINT fk_events_execution FOREIGN KEY (execution_id) REFERENCES executions(id) ON DELETE SET NULL,
      INDEX idx_events_user_created (user_id, created_at)
    ) ENGINE=InnoDB`,
    `CREATE TABLE IF NOT EXISTS audit_log (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      sequence_number INT NOT NULL UNIQUE,
      timestamp VARCHAR(32) NOT NULL,
      actor_username VARCHAR(80) NOT NULL,
      event_type VARCHAR(80) NOT NULL,
      resource_type VARCHAR(80) NOT NULL DEFAULT 'system',
      resource_id VARCHAR(255) NOT NULL DEFAULT '',
      details_json JSON NULL,
      payload_hash CHAR(64) NOT NULL,
      previous_hash CHAR(64) NOT NULL,
      entry_hash CHAR(64) NOT NULL UNIQUE
    ) ENGINE=InnoDB`,
  ];

  for (const definition of definitions) {
    await pool.query(definition);
  }
  return migrateLegacyTables();
}

module.exports = {
  pool,
  initSchema,
  migrateLegacyTables,
};
