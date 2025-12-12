# LDAP-FIDO Server

LDAP-based Identity Provider with WebAuthn/FIDO2 and LDAP authentication.

## Table of Contents

- [Environment Configuration](#environment-configuration)
- [Setup](#setup)
- [Development](#development)
- [Deployment](#deployment)
- [Documentation](#documentation)
  - [Environment Variables](docs/ENVIRONMENT.md)

---

## Prerequisites

- **Docker** and **Docker Compose** (for backend, Redis, and OpenLDAP)
- **Node.js** (>=22.11.0) and **npm** (>=10.9.0) (for frontend development)

---

## License Compliance

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

This project uses several open-source dependencies. For a complete list of all third-party software and their licenses, see the [LICENSES](LICENSES/) directory and [NOTICE](NOTICE) file.

### License Verification

To verify license compliance:

```bash
# Install dependencies
npm ci

# Check licenses
npx license-checker --production

# Audit dependencies
npm audit
```

## 1. Multi-Environment Setup with Makefile

This project now supports environment-specific Docker Compose and `.env` files for development, production, and test. All workflows are managed via the Makefile.

### Environment Configuration

Environment variables are now organized in the `env/` directory with the following structure:

```
env/
├── client/               # Client-side environment variables
│   ├── development/     # Development environment
│   ├── staging/        # Staging environment
│   ├── production/     # Production environment
│   └── testing/        # Testing environment
└── server/             # Server-side environment variables
    ├── development/
    ├── staging/
    ├── production/
    └── testing/
```

### Initial Setup

1. Copy the example environment files:
   ```bash
   # Server
   cp config/env/server.env.example env/server/development/.env

   # Client (optional; only needed if you run Vite directly)
   cp config/env/client.env.example env/client/development/.env
   ```

2. Update the environment variables in these files according to your setup.

### Compose Files
- `server/docker-compose.development.yml`
- `server/docker-compose.production.yml`
- `server/docker-compose.test.yml`
- `server/docker-compose.staging.yml`
- `server/Makefile`

For more details, see [env/README.md](env/README.md).

### Makefile Usage (from `server/` directory)

All workflow commands should now be run from within the `server/` directory, or by referencing the Makefile and files in `server/`. **Note:** Make sure to run all Docker Compose commands from within the `server/` directory, as this is now the working directory for Docker Compose.

**Start stacks:**
- Development:   `make dev`
- Test:          `make test`
- Staging:       `make staging`
- Production:    `make prod`

**Stop and remove containers/volumes:**
- Development:   `make down-dev`
- Test:          `make down-test`
- Staging:       `make down-staging`
- Production:    `make down-prod`
- All at once:   `make down-all`

**Clean up all unused Docker resources:**
- `make clean`

All targets use the correct Compose and `.env` file for their environment (from `env/server/<environment>/.env`). No need to manually edit Compose or env files!

Frontend workflows are available via `client/Makefile`.

---

## 3. Start the Frontend (React/Vite)

Open a new terminal, then:

```bash
cd client
npm install
npm run dev
```

Or using the Makefile:

```bash
cd client
make dev
```

- The frontend will be available at [https://rpid.example.org:5173](https://rpid.example.org:5173)
- It proxies API requests to the backend at port 3000.

---

## 4. Demo the App

- Visit [https://rpid.example.org:5173](https://rpid.example.org:5173) in your browser.
- Use the login form to authenticate with LDAP credentials.
- On successful login, user info will be displayed.
- Error and consent pages are available as React components (integrate them into flows as needed).

---

## 5. Run Backend Tests

In another terminal:

```bash
cd server
npm install
npm test
```

- Runs Jest/Supertest tests for backend endpoints.

---

## 6. Stopping the App

To stop all services:

```bash
cd server
make down-dev
```

---

## Notes

- Update LDAP credentials and protocol configs as needed in `config/`.
 
