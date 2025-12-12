// Admin section routes (role-based access)
import express from 'express';
import pool from '../db/index.js';
import requireRole from '../middlewares/requireRole.js';

const router = express.Router();

// GET /api/admin/app-vars -- Get application variables (admin, auditor)
router.get('/app-vars', requireRole(['admin', 'auditor'], { readOnly: true }), (req, res) => {
  const appVars = {
    // Server configuration
    NODE_ENV: process.env.NODE_ENV,
    SERVER_PORT: process.env.SERVER_PORT ?? 3000,
    
    // Authentication
    SESSION_SECRET: process.env.SESSION_SECRET ? '***' : undefined,
    SESSION_COOKIE_MAX_AGE: process.env.SESSION_COOKIE_MAX_AGE ?? 86400000, // 24h default
    
    // LDAP Configuration
    LDAP_URL: process.env.LDAP_URL,
    LDAP_SEARCH_BASE_USERS: process.env.LDAP_SEARCH_BASE_USERS,
    LDAP_SEARCH_FILTER: process.env.LDAP_SEARCH_FILTER,
    LDAP_ADMIN_GROUP_CN: process.env.LDAP_ADMIN_GROUP_CN,
    
    // CORS
    CORS_ORIGINS: process.env.CORS_ORIGINS ?? 'http://localhost:5173',
    
    // Logging
    LOG_LEVEL: process.env.LOG_LEVEL ?? 'info',
    
    // Other configurations
    READ_ONLY: req.readOnly ?? false
  };
  
  res.json(appVars);
});

// GET /api/admin/db-config -- view DB config (admin, auditor)
router.get('/db-config', requireRole(['admin', 'auditor'], { readOnly: true }), (req, res) => {
  const config = {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: '***', // Never expose password in response
  };
  res.json({ config, readOnly: req.readOnly });
});

// PUT /api/admin/db-config -- update DB config (admin only)
router.put('/db-config', requireRole(['admin']), (req, res) => {
  const { host, port, database, user, password } = req.body;
  // In production, you would persist this securely and reload config
  process.env.DB_HOST = host;
  process.env.DB_PORT = port;
  process.env.DB_NAME = database;
  process.env.DB_USER = user;
  process.env.DB_PASSWORD = password;
  res.json({ success: true });
});

export default router;
