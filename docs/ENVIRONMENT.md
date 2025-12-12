# Environment Variables Reference

This document describes all environment variables used in the LDAP-FIDO Server project.

## Server Environment Variables

### Application
- `NODE_ENV` - Node.js environment (`development`, `production`, `test`)
- `SERVER_DEFAULT_PORT` - Port the server listens on (default: `3000`)
- `FRONTEND_DEFAULT_PORT` - Default frontend port (used for URL generation)
- `SERVER_SESSION_SECRET` - Secret used to sign session cookies
- `SERVER_CORS_ORIGIN` - Allowed CORS origins (comma-separated)
- `FRONTEND_URL` - Public URL of the frontend (used in redirects/links)
- `BACKEND_PUBLIC_URL` - Public URL of the backend (used to build absolute download/upload links)
- `DEBUG_LOGS` - Enable verbose debug logs (`true|1|yes|on`)

### Database
- `DB_HOST` - Database host (default: `postgres` for Docker, `localhost` otherwise)
- `DB_PORT` - Database port (default: `5432`)
- `DB_NAME` - Database name
- `DB_USER` - Database username
- `DB_PASSWORD` - Database password

If you are using Postgres via Docker Compose, these variables may also be used:
- `POSTGRES_USER`
- `POSTGRES_DB`
- `POSTGRES_PASSWORD`

### Redis
- `REDIS_HOST` - Redis host (default: `redis` for Docker, `localhost` otherwise)
- `REDIS_PORT` - Redis port (default: `6379`)
- `REDIS_PASSWORD` - Redis password (optional)
- `REDIS_DB` - Redis database index

### LDAP
- `LDAP_URL` - LDAP server URL (e.g., `ldap://openldap:389`)
- `LDAP_BASE_DN` - Base DN for LDAP searches
- `LDAP_ADMIN_DN` - DN for admin binding to LDAP
- `LDAP_ADMIN_PASSWORD` - Password for admin bind DN
- `LDAP_SEARCH_BASE_USERS` - Base DN for user searches (e.g., `ou=users,dc=example,dc=org`)
- `LDAP_SEARCH_FILTER` - LDAP search filter for users (e.g., `(uid={{username}})`)
- `LDAP_SEARCH_BASE_GROUPS` - Base DN for group searches
- `LDAP_APP_ADMIN_GROUP_CN` - Group CN for application admins

### WebAuthn (FIDO2)
- `FIDO2_RP_ID` - WebAuthn RP ID (domain)
- `FIDO2_RP_NAME` - WebAuthn RP display name
- `FIDO2_RP_ORIGIN` - WebAuthn expected origin (scheme + host + port)
- `FIDO2_USER_VERIFICATION` - `required|preferred|discouraged`
- `FIDO2_ALLOWCREDENTIALS_TRANSPORTS` - Comma-separated transports

### Email (SMTP) / TOTP
- `SMTP_ENABLED` - Enable SMTP-based TOTP delivery (`true|false`)
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_SSL` - Use SMTPS
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_EMAIL_FROM_NAME`
- `SMTP_EMAIL_FROM_ADDRESS`

TOTP settings:
- `SMTP_TOTP_STEP`
- `SMTP_TOTP_WINDOW`
- `SMTP_TOTP_LENGTH`

### Session cookies
- `SESSION_COOKIE_SAMESITE`
- `SESSION_COOKIE_SECURE`
- `SESSION_COOKIE_DOMAIN`

## Client Environment Variables

- `VITE_BACKEND_URL` - Backend URL used by the Vite dev proxy (e.g. `http://localhost:3000`)
- `VITE_CLIENT_PORT` - Port used by Vite dev server (default: `5173`)
- `VITE_HTTPS` - Enable HTTPS in Vite dev server (`true|false`)
- `VITE_HTTPS_CERT` - Path to HTTPS certificate file
- `VITE_HTTPS_KEY` - Path to HTTPS key file
- `VITE_DEBUG_LOGS` - Enable verbose debug logs (`true|1|yes|on`)

## Development vs Production

For Docker Compose workflows, environment variables are provided via the `--env-file` configured in the `server/Makefile`.

For local development (running Node/Vite directly), use the service-level `.env` files (e.g. `server/.env*`, `client/.env*`) as supported by dotenv/Vite.

## Setting Up a New Environment

1. Copy the example files:
   ```bash
   cp config/env/server.env.example env/server/development/.env
   cp config/env/client.env.example env/client/development/.env
   ```

2. Update the values in the new `.env` files
3. Never commit sensitive information to version control

## Best Practices

1. Always use environment variables for configuration
2. Never commit `.env` files with secrets
3. Use `.env.example` files to document required variables
4. Keep development and production configurations separate
5. Use `.env.local` for local overrides (already in .gitignore)
