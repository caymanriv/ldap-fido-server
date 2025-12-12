# LDAP-FIDO Server Backend

Node.js backend for LDAP-based IdP with WebAuthn/FIDO2 and LDAP authentication.

## Features

- LDAP authentication (OpenLDAP)
- Session management with Redis
- Security best practices (helmet, cors)

## Setup

### Environment Configuration

Environment variables are organized in the project root's `env/` directory. For local development:

1. Copy the example environment files:
   ```bash
   # From the project root
   cp ../config/env/server.env.example ../env/server/development/.env
   ```

2. Update the environment variables in `env/server/development/.env`

### Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the development server:
   ```bash
   npm run dev
   ```

### Docker Setup

Use the provided `docker-compose` files with the Makefile:

```bash
# Start development environment
make dev

# Stop development environment
make down-dev
```

For other environments (staging, production), use the corresponding make targets.

See the main [README.md](../README.md) for more details.

## Health Check

- `GET /health` returns `{ status: 'ok' }`
