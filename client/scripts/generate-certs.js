#!/usr/bin/env node
/*
 Auto-generate local HTTPS certs for Vite dev server using selfsigned (no sudo required).
 - Uses VITE_DOMAIN from env/client/development/.env for certificate generation
 - Generates certs with CN and SAN = VITE_DOMAIN only
 - Saves to client/certs/
 - Updates env/client/development/.env with HTTPS settings (VITE_HTTPS, VITE_HTTPS_KEY, VITE_HTTPS_CERT)
 - Safe to re-run; will not overwrite existing files if present
*/
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

/**
 * Parse .env file content into an object
 */
function parseEnvFile(envText) {
  return envText.split('\n').reduce((acc, line) => {
    // Skip comments and empty lines
    if (line.trim() === '' || line.startsWith('#')) return acc;
    
    const match = line.match(/^([^=]+)=(.*)$/);
    if (match) {
      // Remove surrounding quotes if present
      const value = match[2].replace(/^['"]|['"]$/g, '');
      acc[match[1]] = value;
    }
    return acc;
  }, {});
}

async function main() {
  try {
    const clientRoot = path.resolve(__dirname, '..');
    const projectRoot = path.resolve(clientRoot, '..');
    const envPath = path.join(projectRoot, 'env', 'client', 'development', '.env');
    if (!fs.existsSync(envPath)) {
      console.warn(`[generate-certs] .env file not found at ${envPath}`);
      process.exit(0);
    }
    
    const envText = fs.readFileSync(envPath, 'utf8');
    const env = parseEnvFile(envText);
    
    // Get domain from VITE_DOMAIN or use a default
    const domain = env.VITE_DOMAIN || 'rpid.example.org';
    console.log(`[generate-certs] Using domain: ${domain}`);
    
    // Check if mkcert is installed and accessible
    const mkcertPath = '/usr/bin/mkcert';
    try {
      if (!fs.existsSync(mkcertPath)) {
        throw new Error('mkcert not found at ' + mkcertPath);
      }
      // Test if mkcert is executable
      fs.accessSync(mkcertPath, fs.constants.X_OK);
    } catch (e) {
      console.warn('[generate-certs] mkcert is not installed or not executable. HTTPS will be disabled.');
      console.warn('  Install mkcert: https://github.com/FiloSottile/mkcert');
      console.warn('  Linux: sudo apt install mkcert');
      console.warn('  macOS: brew install mkcert');
      console.warn('  Windows: choco install mkcert');
      process.exit(0);
    }

    // Check if mkcert is properly set up with a root CA
    try {
      const caroot = execSync(`${mkcertPath} -CAROOT 2>/dev/null`, { encoding: 'utf8' }).trim();
      if (!fs.existsSync(path.join(caroot, 'rootCA.pem'))) {
        console.warn('[generate-certs] mkcert root CA not found. Please run:');
        console.warn('  mkcert -install');
        process.exit(0);
      }
    } catch (e) {
      console.warn('[generate-certs] Error checking mkcert installation:', e.message);
      console.warn('  Please ensure mkcert is properly installed and in your PATH');
      process.exit(0);
    }
    
    // Generate certificates using mkcert
    const certsDir = path.join(clientRoot, 'certs');
    console.log(`[generate-certs] Generating development certificates for ${domain}...`);
    
    // Create certs directory if it doesn't exist
    if (!fs.existsSync(certsDir)) {
      fs.mkdirSync(certsDir, { recursive: true });
    }
    
    const keyPath = path.join(certsDir, `${domain}-key.pem`);
    const certPath = path.join(certsDir, `${domain}.pem`);
    
    try {
      // Generate certificates with mkcert using full path
      execSync(
        `${mkcertPath} -key-file ${keyPath} -cert-file ${certPath} ${domain} "*.${domain}" localhost 127.0.0.1 ::1`,
        { stdio: 'inherit' }
      );
      
      console.log(`[generate-certs] Certificates generated successfully in ${certsDir}`);
      
      // Set proper permissions on the key file
      try {
        fs.chmodSync(keyPath, 0o600);
      } catch (e) {
        console.warn(`[generate-certs] Warning: Could not set permissions on ${keyPath}:`, e.message);
      }
      
    } catch (e) {
      console.warn('[generate-certs] Failed to generate certificates with mkcert. HTTPS will be disabled.');
      console.warn('  Error:', e.message);
      process.exit(0);
    }
    
    // Function to update .env file
    const updateEnvFile = (envText, updates) => {
      let lines = envText.split('\n');
      let updated = false;
      
      Object.entries(updates).forEach(([key, value]) => {
        const regex = new RegExp(`^${key}=`);
        const existingIndex = lines.findIndex(line => regex.test(line));
        const newLine = `${key}=${value}`;
        
        if (existingIndex >= 0) {
          if (lines[existingIndex] !== newLine) {
            lines[existingIndex] = newLine;
            updated = true;
          }
        } else {
          lines.push(newLine);
          updated = true;
        }
      });
      
      return updated ? lines.join('\n').trim() + '\n' : envText;
    };
    
    // Update the .env file with relative paths
    const updatedEnvText = updateEnvFile(envText, {
      'VITE_HTTPS': 'true',
      'VITE_HTTPS_KEY': `./certs/${domain}-key.pem`,
      'VITE_HTTPS_CERT': `./certs/${domain}.pem`
    });
    
    if (updatedEnvText !== envText) {
      fs.writeFileSync(envPath, updatedEnvText);
      console.log(`[generate-certs] Updated ${envPath} with HTTPS settings.`);
    }
    
    console.log('[generate-certs] Done.');
    console.log('\n📝 Add this to your /etc/hosts file:');
    console.log(`127.0.0.1    ${domain}`);
    console.log(`::1          ${domain}`);
    console.log('\n🔑 Trust instructions:');
    console.log('- Firefox: Go to about:preferences#privacy, scroll to \'Certificates\', click \'View Certificates\', go to \'Authorities\', and import the root CA');
    console.log('- Chrome/Chromium: Run `mkcert -install` to trust the CA system-wide');
    
  } catch (err) {
    console.warn('[generate-certs] Error:', err && err.message ? err.message : err);
    console.warn('[generate-certs] HTTPS will be disabled. Run with --debug for more details.');
    process.exit(0);
  }
}

main();
