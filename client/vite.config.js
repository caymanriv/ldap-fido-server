import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';

// Resolve the absolute path to the .env file
const envDir = path.resolve(process.cwd(), '../env/client/development');

export default defineConfig(({ mode }) => {
  // Load environment variables from the correct directory
  const env = loadEnv(mode, envDir, '');
  
  // Resolve certificate paths relative to the project root
  const keyPath = path.resolve(__dirname, env.VITE_HTTPS_KEY);
  const certPath = path.resolve(__dirname, env.VITE_HTTPS_CERT);
  
  // Verify certificate files exist with better error messages
  if (!fs.existsSync(keyPath)) {
    console.error(`❌ SSL Key not found at: ${keyPath}`);
    console.error(`   (resolved from: ${env.VITE_HTTPS_KEY})`);
    console.error('Please run: npm run postinstall');
    process.exit(1);
  }
  
  if (!fs.existsSync(certPath)) {
    console.error(`❌ SSL Certificate not found at: ${certPath}`);
    console.error(`   (resolved from: ${env.VITE_HTTPS_CERT})`);
    console.error('Please run: npm run postinstall');
    process.exit(1);
  }
  
  console.log('✅ Certificate files verified:');
  console.log(`   Key: ${keyPath}`);
  console.log(`   Cert: ${certPath}`);
  
  // Debug: Log loaded environment variables
  console.log('Vite Environment Variables:');
  console.log('- VITE_BACKEND_URL:', env.VITE_BACKEND_URL);
  console.log('- VITE_CLIENT_PORT:', env.VITE_CLIENT_PORT);
  console.log('- NODE_ENV:', process.env.NODE_ENV);
  console.log('- Mode:', mode);
  console.log('- VITE_HTTPS:', env.VITE_HTTPS);
  console.log('- VITE_HTTPS_CERT:', certPath);
  console.log('- VITE_HTTPS_KEY:', keyPath);

  // Configure HTTPS if VITE_HTTPS is true
  const httpsConfig = env.VITE_HTTPS === 'true' ? {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
  } : false;

  return {
    envDir: path.dirname(envDir), // Tell Vite where to find .env files
    plugins: [react()],
    server: {
      port: parseInt(env.VITE_CLIENT_PORT ?? '5173'),
      host: 'rpid.example.org', // Use the exact domain that matches your RP ID
      strictPort: true,
      https: httpsConfig,
      hmr: {
        host: 'rpid.example.org',
        protocol: 'wss',
        port: 5173
      },
      allowedHosts: [
        'rpid.example.org',
        'localhost',
        '127.0.0.1',
        '::1',
        '0.0.0.0'
      ],
      proxy: {
        '/api': {
          target: env.VITE_BACKEND_URL,
          changeOrigin: true,
          secure: false,
          ws: true,
          configure: (proxy, _options) => {
            proxy.on('error', (err, _req, _res) => {
              console.error('Proxy error:', err);
            });
            proxy.on('proxyReq', (proxyReq, req, _res) => {
              console.log('Proxying request:', req.method, req.url);
              const useHttps = env.VITE_HTTPS === 'true';
              const clientPort = env.VITE_CLIENT_PORT ?? '5173';
              const clientOrigin = `${useHttps ? 'https' : 'http'}://rpid.example.org:${clientPort}`;
              proxyReq.setHeader('x-forwarded-proto', useHttps ? 'https' : 'http');
              proxyReq.setHeader('x-forwarded-host', 'rpid.example.org');
              proxyReq.setHeader('origin', clientOrigin);
            });
          }
        },
        '/admin': {
          target: env.VITE_BACKEND_URL ?? 'http://localhost:3000',
          changeOrigin: true,
          secure: false,
          ws: true,
          configure: (proxy, _options) => {
            proxy.on('error', (err, _req, _res) => {
              console.error('Proxy error:', err);
            });
          }
        },
      },
    },
  };
});
