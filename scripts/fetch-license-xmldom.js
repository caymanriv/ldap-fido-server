import fs from 'fs';
import path from 'path';
import https from 'https';

const LICENSES_DIR = path.join(__dirname, '..', 'LICENSES');

// Ensure LICENSES directory exists
if (!fs.existsSync(LICENSES_DIR)) {
  fs.mkdirSync(LICENSES_DIR, { recursive: true });
}

// Create xmldom directory if it doesn't exist
const xmldomDir = path.join(LICENSES_DIR, '@xmldom');
if (!fs.existsSync(xmldomDir)) {
  fs.mkdirSync(xmldomDir);
}

const licensePath = path.join(xmldomDir, 'xmldom.LICENSE');

// Skip if already downloaded
if (fs.existsSync(licensePath)) {
  console.log('License already exists, skipping...');
  return;
}

// Try different GitHub URLs for xmldom license
const urls = [
  'https://raw.githubusercontent.com/xmldom/xmldom/master/LICENSE',
  'https://raw.githubusercontent.com/xmldom/xmldom/main/LICENSE',
  'https://raw.githubusercontent.com/xmldom/xmldom/master/LICENSE.md',
  'https://raw.githubusercontent.com/xmldom/xmldom/main/LICENSE.md'
];

const fetchLicense = async (url) => {
  return new Promise((resolve) => {
    https.get(url, { headers: { 'User-Agent': 'node.js' } }, (res) => {
      if (res.statusCode === 200) {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          fs.writeFileSync(licensePath, `Package: @xmldom/xmldom@0.9.8\n`);
          fs.appendFileSync(licensePath, `Repository: https://github.com/xmldom/xmldom\n\n`);
          fs.appendFileSync(licensePath, '--- LICENSE ---\n');
          fs.appendFileSync(licensePath, data);
          console.log('Successfully fetched xmldom license');
          resolve(true);
        });
      } else {
        resolve(false);
      }
    }).on('error', () => resolve(false));
  });
};

// Try each URL until we find one that works
const main = async () => {
  console.log('Trying to fetch xmldom license...');
  for (const url of urls) {
    const success = await fetchLicense(url);
    if (success) {
      break;
    }
  }
};

main().catch(console.error);
