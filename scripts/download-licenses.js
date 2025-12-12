import fs from 'fs';
import path from 'path';
import https from 'https';
import { execSync } from 'child_process';

const LICENSES_DIR = path.join(__dirname, '..', 'LICENSES');

// Ensure LICENSES directory exists
if (!fs.existsSync(LICENSES_DIR)) {
  fs.mkdirSync(LICENSES_DIR, { recursive: true });
}

// Get production dependencies
const getDependencies = () => {
  const result = execSync('npm ls --production --json --depth=0', { encoding: 'utf8' });
  const { dependencies } = JSON.parse(result);
  return Object.entries(dependencies).map(([name, pkg]) => ({
    name,
    version: pkg.version,
    repository: pkg.repository || ''
  }));
};

// Download license file from npm
const downloadLicense = async (pkg) => {
  const licensePath = path.join(LICENSES_DIR, `${pkg.name}.LICENSE`);
  
  // Skip if already downloaded
  if (fs.existsSync(licensePath)) {
    return;
  }

  const url = `https://registry.npmjs.org/${pkg.name}/${pkg.version}`;
  
  return new Promise((resolve) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const pkgInfo = JSON.parse(data);
          const licenseText = pkgInfo.license || 'No license information found';
          fs.writeFileSync(licensePath, `Package: ${pkg.name}@${pkg.version}\n`);
          fs.appendFileSync(licensePath, `Repository: ${pkg.repository || 'Not specified'}\n\n`);
          fs.appendFileSync(licensePath, '--- LICENSE ---\n');
          fs.appendFileSync(licensePath, typeof licenseText === 'string' ? licenseText : JSON.stringify(licenseText, null, 2));
          console.log(`Downloaded license for ${pkg.name}@${pkg.version}`);
        } catch (error) {
          console.error(`Error processing ${pkg.name}:`, error.message);
        }
        resolve();
      });
    }).on('error', (error) => {
      console.error(`Error downloading ${pkg.name}:`, error.message);
      resolve();
    });
  });
};

// Main function
const main = async () => {
  console.log('Downloading licenses for production dependencies...');
  const dependencies = getDependencies();
  
  for (const pkg of dependencies) {
    await downloadLicense(pkg);
  }
  
  console.log('\nLicense files downloaded to LICENSES/ directory');
  console.log('Don\'t forget to check each license file for accuracy!');
};

main().catch(console.error);
