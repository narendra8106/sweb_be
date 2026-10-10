const path = require('path');
require('dotenv').config();

const PROJECT_ROOT = path.resolve(__dirname, '..');
const configuredDatabaseUrl = process.env.DB_HOST ? '' : process.env.DATABASE_URL;

module.exports = {
  PORT: Number(process.env.PORT || 8000),
  DATABASE_URL: configuredDatabaseUrl || '',
  DB_HOST: process.env.DB_HOST || '127.0.0.1',
  DB_PORT: Number(process.env.DB_PORT || 3306),
  DB_NAME: process.env.DB_NAME || 'wasm_sandbox',
  DB_USER: process.env.DB_USER || 'wasm_user',
  DB_PASSWORD: process.env.DB_PASSWORD || '',
  SECRET_KEY: process.env.SECRET_KEY,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '2h',
  UPLOAD_DIR: process.env.UPLOAD_DIR || path.join(PROJECT_ROOT, 'storage', 'modules'),
  EXAMPLES_DIR: path.join(PROJECT_ROOT, 'examples'),
  MAX_UPLOAD_SIZE: Number.parseInt(process.env.MAX_UPLOAD_SIZE || '5242880', 10),
  MAX_INPUT_SIZE: Number.parseInt(process.env.MAX_INPUT_SIZE || '10240', 10),
  MAX_OUTPUT_SIZE: Number.parseInt(process.env.MAX_OUTPUT_SIZE || '65536', 10),
  DEFAULT_ADMIN_EMAIL: process.env.DEFAULT_ADMIN_EMAIL || 'admin@wasm.local',
  DEFAULT_ADMIN_PASSWORD: process.env.DEFAULT_ADMIN_PASSWORD || 'Admin123!',
};
