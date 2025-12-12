// PostgreSQL connection pool using 'pg'
import dotenv from 'dotenv';
import pg from 'pg';
const { Pool } = pg;

dotenv.config();

const pool = new Pool({
  host: process.env.DB_HOST || 'postgres',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: 10,
  idleTimeoutMillis: 30000,
  // Allow more time for inter-container networking / DB warmup
  connectionTimeoutMillis: parseInt(process.env.DB_CONNECTION_TIMEOUT_MS || '30000', 10),
  // Set query and statement timeouts as connection parameters
  options: `-c statement_timeout=${process.env.DB_STATEMENT_TIMEOUT_MS || '30000'}`,
  // Query timeout is handled at the application level
  query_timeout: false
});

export default pool;