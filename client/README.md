# LDAP FIDO Server Frontend

Frontend (React + Vite) for LDAP-FIDO Server.

## Development Setup with HTTPS

This project uses mkcert for local HTTPS development with self-signed certificates. Follow these steps to set it up:

### Prerequisites

1. Install mkcert:
   ```bash
   # Linux
   sudo apt install mkcert
   
   # macOS
   brew install mkcert
   
   # Windows
   choco install mkcert
   ```

### Setting Up Certificates

1. Run the setup script:
   ```bash
   npm run setup:dev-certs
   ```
   
   This will:
   - Create a local Certificate Authority (CA) if it doesn't exist
   - Generate development certificates for `rpid.example.org`
   - Output instructions for trusting the certificates

2. Update your `/etc/hosts` file with:
   ```
   127.0.0.1    rpid.example.org
   ::1          rpid.example.org
   ```

3. Trust the CA certificate (required for WebAuthn to work):
   - **Firefox**: 
     - Go to `about:preferences#privacy`
     - Scroll to 'Certificates' and click 'View Certificates'
     - Go to 'Authorities' and import `~/.local/share/mkcert/rootCA.pem`
   - **Chrome/Chromium**: 
     - The CA should be automatically trusted if you ran `mkcert -install`
     - If not, import `~/.local/share/mkcert/rootCA.pem` into your OS keychain

### Running the Development Server

Use one of these commands:

```bash
# Standard dev server (assumes certs are already set up)
npm run dev

# Or, to ensure certs are generated first:
npm run dev:with-certs
```

Or using the Makefile:

```bash
make dev
make dev-with-certs
```

Access the app at: https://rpid.example.org:5173

### Troubleshooting

- **Certificate errors**: Ensure you've trusted the root CA certificate
- **WebAuthn errors**: Make sure you're accessing the site via `https://rpid.example.org:5173` (not localhost)

## Environment variables

Example environment variables are in `../config/env/client.env.example`.

- `VITE_BACKEND_URL`
- `VITE_CLIENT_PORT`
- `VITE_HTTPS`
- `VITE_HTTPS_CERT`
- `VITE_HTTPS_KEY`
- `VITE_DEBUG_LOGS`

## Build

```bash
npm run build
```

Or:

```bash
make build
```
