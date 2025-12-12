#!/bin/bash
set -e

# Ensure mkcert is installed
if ! command -v mkcert &> /dev/null; then
    echo "Error: mkcert is not installed. Please install it first:"
    echo "  - Linux: sudo apt install mkcert"
    echo "  - macOS: brew install mkcert"
    echo "  - Windows: choco install mkcert"
    exit 1
fi

# Create certs directory if it doesn't exist
mkdir -p certs

# Set domain (can be overridden with DOMAIN env var)
DOMAIN=${DOMAIN:-rpid.example.org}

# Install the local CA (only if not already installed)
if [ ! -f "$HOME/.local/share/mkcert/rootCA.pem" ]; then
    echo "Creating and installing local CA..."
    mkcert -install
else
    echo "Local CA already exists, skipping creation..."
fi

# Generate certificates
set -x  # Show commands being run
mkcert -key-file certs/${DOMAIN}-key.pem \
       -cert-file certs/${DOMAIN}.pem \
       ${DOMAIN} "*.${DOMAIN}" localhost 127.0.0.1 ::1
set +x

echo ""
echo "✅ Certificates generated successfully!"
echo "- Certificate: certs/${DOMAIN}.pem"
echo "- Private key: certs/${DOMAIN}-key.pem"
echo ""
echo "📝 Add this to your /etc/hosts file:"
echo "127.0.0.1    ${DOMAIN}"
echo "::1          ${DOMAIN}"
echo ""
echo "🔑 Trust instructions:"
echo "- Firefox: Go to about:preferences#privacy, scroll to 'Certificates', click 'View Certificates', go to 'Authorities', and import $HOME/.local/share/mkcert/rootCA.pem"
echo "- Chrome/Chromium: The CA should be automatically trusted if you ran mkcert -install"
