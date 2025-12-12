// Script to initialize app_variables table from .env file(s) for any environment
import { existsSync, readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import dotenv from 'dotenv';
import { createRequire } from 'module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables from multiple possible locations
const envPaths = [
  '/app/.env',                      // Docker container path
  resolve(__dirname, '../.env'), // Local development
  resolve(__dirname, '../../.env') // Alternative local path
];

let envPath = null;
for (const p of envPaths) {
  try {
    if (existsSync(p)) {
      envPath = p;
      console.log(`Loading environment from: ${p}`);
      dotenv.config({ path: p });
      break;
    }
  } catch (err) {
    console.warn(`Warning: Could not load .env from ${p}:`, err.message);
  }
}

if (!envPath) {
  console.warn('No .env file found in any standard location. Using process.env only.');
  console.warn('Expected locations:', envPaths);
}

// Database connection with defaults for local development
const pool = new pg.Pool({
  host: process.env.DB_HOST ?? 'postgres',  // Default to service name in Docker
  port: parseInt(process.env.DB_PORT ?? '5432', 10),
  database: process.env.DB_NAME ?? 'ldap_fido',
  user: process.env.DB_USER ?? 'postgres',
  password: process.env.DB_PASSWORD ?? 'postgres',
  connectionTimeoutMillis: 10000, // 10 seconds timeout
  idleTimeoutMillis: 30000, // 30 seconds idle timeout
});

// Group keys by service prefix
const SERVICE_PREFIXES = [
  'LDAP', 'REDIS', 'DB', 'POSTGRES', 
  'CLIENT', 'SERVER', 'NODE', 'SAML', 'OIDC', 'CAS', 'AUTHENTICATOR'
];
function getService(key) {
  for (const prefix of SERVICE_PREFIXES) {
    if (key.toUpperCase().startsWith(prefix)) return prefix.toLowerCase();
  }
  return 'General'; // fallback group
}

function parseEnvFile(filePath) {
  const envContent = readFileSync(filePath, 'utf8');
  const lines = envContent.split('\n');
  const result = [];
  for (const line of lines) {
    if (!line || line.startsWith('#')) continue;
    const idx = line.indexOf('=');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    const service = getService(key);
    result.push({ service, key, value });
  }
  return result;
}

async function main() {
  const envVars = parseEnvFile(envPath);
  for (const { service, key, value } of envVars) {
    await pool.query(
      `INSERT INTO app_variables (service, key, value, description)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (service, key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [service, key, value, null]
    );
  }
  console.log('App variables initialized from .env file.');
  process.exit(0);
}

main().catch(err => {
  console.error('Error initializing app variables:', err);
  process.exit(1);
});
