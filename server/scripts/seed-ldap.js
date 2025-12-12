// Script to seed OpenLDAP with test users
import { existsSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import ldap from 'ldapjs';
import crypto from 'crypto';
import { execSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Try to load environment variables from multiple locations
const envPaths = [
  '/app/.env',                      // Docker container path
  join(__dirname, '.env'),              // Local development
  join(__dirname, '..', '.env'),           // Parent directory
  join(__dirname, '..', '..', '.env'),        // Project root
  join(__dirname, '..', '..', 'server', '.env')  // Server directory
];

let envLoaded = false;
for (const path of envPaths) {
  if (existsSync(path)) {
    console.log(`Loading environment from: ${path}`);
    const envConfig = dotenv.parse(readFileSync(path));
    for (const key in envConfig) {
      process.env[key] = envConfig[key];
    }
    envLoaded = true;
    break;
  }
}

/**
 * Ensure a default posix group exists (used for users' primary gidNumber)
 * @param {Object} client - LDAP client instance
 * @returns {Promise<{dn:string,gidNumber:number}>}
 */
async function ensureDefaultPosixGroup(client) {
  const defaultGroupCN = process.env.LDAP_DEFAULT_GROUP_CN ?? 'users';
  const defaultGroupGID = parseInt(process.env.LDAP_DEFAULT_GID ?? '10000', 10);
  const defaultGroupDN = `cn=${defaultGroupCN},${GROUPS_OU_DN}`;

  const groupEntry = {
    objectClass: ['top', 'posixGroup'],
    cn: defaultGroupCN,
    gidNumber: String(defaultGroupGID)
  };

  await new Promise((resolve, reject) => {
    client.add(defaultGroupDN, groupEntry, (err) => {
      if (err && err.code !== 68) { // 68 = Entry Already Exists
        reject(err);
      } else {
        if (err && err.code === 68) {
          console.log(`Default posix group already exists: ${defaultGroupDN}`);
        } else {
          console.log(`Created default posix group: ${defaultGroupDN}`);
        }
        resolve();
      }
    });
  });

  return { dn: defaultGroupDN, gidNumber: defaultGroupGID };
}

if (!envLoaded) {
  console.warn('No .env file found, using process.env only');
  dotenv.config();
}

/**
 * Generate a SSHA password hash (compatible with most LDAP servers)
 * @param {string} password - The password to hash
 * @returns {string} SSHA hashed password string
 */
function hashPassword(password) {
  // Generate a random salt (8 bytes = 16 hex chars)
  const salt = crypto.randomBytes(8);
  
  // Create SHA-1 hash of password + salt
  const hash = crypto.createHash('sha1');
  hash.update(password, 'utf8');
  hash.update(salt);
  const hashed = hash.digest();
  
  // Combine the hash and salt
  const hashPlusSalt = Buffer.alloc(hashed.length + salt.length);
  hashPlusSalt.set(hashed);
  hashPlusSalt.set(salt, hashed.length);
  
  // Return as base64-encoded string with {SSHA} prefix
  return `{SSHA}${hashPlusSalt.toString('base64')}`;
}

function createSeededRng(seedStr) {
  if (!seedStr) return null;
  const seed = crypto.createHash('sha256').update(String(seedStr)).digest();
  let state = seed.readUInt32LE(0) ^ seed.readUInt32LE(4) ^ seed.readUInt32LE(8) ^ seed.readUInt32LE(12);
  return {
    nextUInt32: () => {
      state = (Math.imul(1664525, state) + 1013904223) >>> 0;
      return state;
    },
    int: (min, max) => {
      const r = (state = (Math.imul(1664525, state) + 1013904223) >>> 0);
      return min + (r % (max - min + 1));
    },
    float: () => {
      const r = (state = (Math.imul(1664525, state) + 1013904223) >>> 0);
      return r / 0x100000000;
    }
  };
}

function isTruthy(value) {
  if (value == null) return false;
  if (typeof value === 'boolean') return value;
  const s = String(value).trim().toLowerCase();
  return s === 'true' || s === '1' || s === 'yes' || s === 'on';
}

function pick(rng, arr) {
  const idx = rng ? rng.int(0, arr.length - 1) : crypto.randomInt(0, arr.length);
  return arr[idx];
}

function normalizeUid(s) {
  return String(s)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '')
    .slice(0, 20);
}

function generateRandomUsers({ baseDnUsers, baseUid, gidNumber, defaultShell }) {
  const count = parseInt(process.env.LDAP_SEED_RANDOM_USERS_COUNT ?? '20', 10);
  const adminsCount = parseInt(process.env.LDAP_SEED_RANDOM_ADMINS_COUNT ?? '1', 10);
  const seed = process.env.LDAP_SEED_RANDOM_SEED;
  const rng = createSeededRng(seed);
  const password = process.env.LDAP_SEED_DEFAULT_PASSWORD ?? 'password123';
  const domain = process.env.LDAP_SEED_EMAIL_DOMAIN ?? process.env.LDAP_DOMAIN ?? 'example.org';
  const randomPasswords = isTruthy(process.env.LDAP_SEED_RANDOM_PASSWORDS);

  const firstNames = [
    'Alex','Sam','Jordan','Taylor','Casey','Morgan','Riley','Jamie','Chris','Avery',
    'Drew','Cameron','Quinn','Parker','Reese','Robin','Hayden','Logan','Kai','Noah'
  ];
  const lastNames = [
    'Smith','Johnson','Williams','Brown','Jones','Garcia','Miller','Davis','Rodriguez','Martinez',
    'Hernandez','Lopez','Gonzalez','Wilson','Anderson','Thomas','Taylor','Moore','Jackson','Martin'
  ];

  const startUid = baseUid + 100;
  const usedUids = new Set();
  const users = [];

  for (let i = 0; i < count; i++) {
    const givenName = pick(rng, firstNames);
    const sn = pick(rng, lastNames);
    const suffix = rng ? rng.int(10, 9999) : crypto.randomInt(10, 10000);
    const uid = (() => {
      const candidateBase = normalizeUid(`${givenName[0]}${sn}`);
      let candidate = normalizeUid(`${candidateBase}${suffix}`);
      while (usedUids.has(candidate)) {
        const s = rng ? rng.int(10, 9999) : crypto.randomInt(10, 10000);
        candidate = normalizeUid(`${candidateBase}${s}`);
      }
      usedUids.add(candidate);
      return candidate;
    })();

    const cn = `${givenName} ${sn}`;
    const mail = `${uid}@${domain}`;
    const uidNumber = String(startUid + i);
    const homeDirectory = `/home/${uid}`;
    const seedPassword = randomPasswords ? crypto.randomBytes(6).toString('hex') : password;

    users.push({
      dn: `uid=${uid},${baseDnUsers}`,
      attributes: {
        objectClass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson', 'posixAccount', 'ldapPublicKey'],
        uid,
        sn,
        givenName,
        cn,
        displayName: cn,
        mail,
        userPassword: hashPassword(seedPassword),
        uidNumber,
        gidNumber: String(gidNumber),
        homeDirectory,
        loginShell: defaultShell
      },
      isAdmin: i < adminsCount,
      seedPassword
    });
  }

  return users;
}

const BASE_DN = process.env.LDAP_BASE_DN ?? 'dc=example,dc=org';
const USERS_OU_DN = `ou=users,${BASE_DN}`;
const GROUPS_OU_DN = `ou=groups,${BASE_DN}`;

// Validate required environment variables
const REQUIRED_ENV = ['LDAP_URL', 'LDAP_ADMIN_DN', 'LDAP_ADMIN_PASSWORD'];
for (const v of REQUIRED_ENV) {
  if (!process.env[v]) {
    console.error(`Missing required environment variable: ${v}`);
    process.exit(1);
  }
}

/**
 * Wait for LDAP server to be ready
 * @param {string} url - LDAP server URL
 * @param {number} maxAttempts - Maximum number of connection attempts
 * @param {number} initialDelayMs - Initial delay between attempts in milliseconds
 * @returns {Promise<void>}
 */
async function waitForLdap(url, maxAttempts = 20, initialDelayMs = 3000) {
  let attempt = 1;
  let delayMs = initialDelayMs;
  let lastError = null;
  
  console.log(`Attempting to connect to LDAP server at ${url}...`);
  
  while (attempt <= maxAttempts) {
    console.log(`[Attempt ${attempt}/${maxAttempts}] Connecting to LDAP...`);
    
    try {
      const client = ldap.createClient({
        url: url,
        tlsOptions: {
          rejectUnauthorized: process.env.NODE_ENV !== 'development'
        },
        reconnect: false,
        timeout: 10000,
        connectTimeout: 10000
      });
      
      // Wrap client operations in a promise
      await new Promise((resolve, reject) => {
        client.on('connectError', (err) => {
          reject(new Error(`LDAP connection error: ${err.message}`));
        });
        
        client.bind(process.env.LDAP_ADMIN_DN, process.env.LDAP_ADMIN_PASSWORD, (err) => {
          if (err) {
            reject(new Error(`LDAP bind failed: ${err.message}`));
          } else {
            console.log('✓ LDAP bind successful');
            client.unbind(() => {
              client.destroy();
              resolve();
            });
          }
        });
      });
      
      // If we get here, connection was successful
      return;
      
    } catch (error) {
      lastError = error;
      console.warn(`Attempt ${attempt} failed: ${error.message}`);
      
      if (attempt < maxAttempts) {
        // Exponential backoff with jitter
        const jitter = Math.random() * 1000; // 0-1s jitter
        const waitTime = delayMs + jitter;
        console.log(`Retrying in ${Math.round(waitTime / 1000)} seconds...`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
        delayMs = Math.min(delayMs * 2, 30000); // Cap at 30s
      }
      
      attempt++;
    }
  }
  
  // If we get here, all attempts failed
  throw new Error(`Failed to connect to LDAP server after ${maxAttempts} attempts: ${lastError?.message ?? 'Unknown error'}`);
}

/**
 * Check if required LDAP schema for SSH public keys exists
 * @param {Object} client - LDAP client instance
 * @returns {Promise<boolean>} - True if schema exists, false otherwise
 */
async function checkLdapSchema(client) {
  return new Promise((resolve, reject) => {
    client.search('cn=schema,cn=config', {
      scope: 'one',
      filter: '(cn=openssh-lpk)'
    }, (err, res) => {
      if (err) {
        if (err.name === 'NoSuchObjectError') {
          console.warn('WARNING: LDAP schema for SSH public keys is missing.');
          resolve(false);
        } else {
          reject(err);
        }
        return;
      }

      let found = false;
      res.on('searchEntry', (entry) => {
        console.log('Found SSH public key schema:', entry.objectName);
        found = true;
      });

      res.on('error', (err) => {
        reject(err);
      });

      res.on('end', () => {
        if (!found) {
          console.warn('WARNING: LDAP schema for SSH public keys is missing.');
        }
        resolve(found);
      });
    });
  });
}

/**
 * Ensure organizational structure exists
 * @param {Object} client - LDAP client instance
 * @returns {Promise<void>}
 */
async function ensureOrganizationalUnits(client) {
  const ous = [
    {
      dn: USERS_OU_DN,
      attributes: {
        objectClass: ['organizationalUnit', 'top'],
        ou: 'users',
        description: 'Users organizational unit'
      }
    },
    {
      dn: GROUPS_OU_DN,
      attributes: {
        objectClass: ['organizationalUnit', 'top'],
        ou: 'groups',
        description: 'Groups organizational unit'
      }
    }
  ];

  for (const ou of ous) {
    try {
      await new Promise((resolve, reject) => {
        client.add(ou.dn, ou.attributes, (err) => {
          if (err && err.code !== 68) { // 68 = Entry Already Exists
            reject(err);
          } else {
            if (err && err.code === 68) {
              console.log(`Organizational unit already exists: ${ou.dn}`);
            } else {
              console.log(`Created organizational unit: ${ou.dn}`);
            }
            resolve();
          }
        });
      });
    } catch (error) {
      console.error(`Error creating organizational unit ${ou.dn}:`, error.message);
      throw error;
    }
  }
}

/**
 * Ensure admin group exists
 * @param {Object} client - LDAP client instance
 * @returns {Promise<string>} - DN of the admin group
 */
async function ensureAdminGroup(client) {
  const adminGroupCN = process.env.LDAP_APP_ADMIN_GROUP_CN ?? 'admin';
  const adminGroupDN = `cn=${adminGroupCN},${GROUPS_OU_DN}`;
  
  const adminGroup = {
    objectClass: ['groupOfNames', 'top'],
    cn: adminGroupCN,
    description: 'Administrators group',
    member: [`cn=admin,${BASE_DN}`] // Add the default admin user
  };
  
  try {
    await new Promise((resolve, reject) => {
      client.add(adminGroupDN, adminGroup, (err) => {
        if (err && err.code !== 68) { // 68 = Entry Already Exists
          reject(err);
        } else {
          if (err && err.code === 68) {
            console.log(`Admin group already exists: ${adminGroupDN}`);
          } else {
            console.log(`Created admin group: ${adminGroupDN}`);
          }
          resolve();
        }
      });
    });
    return adminGroupDN;
  } catch (error) {
    console.error(`Error creating admin group ${adminGroupDN}:`, error.message);
    throw error;
  }
}

/**
 * Create users and add to admin group
 * @param {Object} client - LDAP client instance
 * @param {string} adminGroupDN - DN of the admin group
 * @returns {Promise<void>}
 */
async function ensureUsers(client, adminGroupDN, defaultGroup) {
  const defaultShell = process.env.LDAP_DEFAULT_SHELL ?? '/bin/bash';
  const baseUid = parseInt(process.env.LDAP_POSIX_BASE_UID ?? '10000', 10);

  const password = process.env.LDAP_SEED_DEFAULT_PASSWORD ?? 'password123';
  const users = [
    {
      dn: `uid=jsmith,${USERS_OU_DN}`,
      attributes: {
        objectClass: [
          'top',
          'person',
          'organizationalPerson',
          'inetOrgPerson',
          'posixAccount',
          'ldapPublicKey'
        ],
        uid: 'jsmith',
        sn: 'Smith',
        givenName: 'John',
        cn: 'John Smith',
        displayName: 'John Smith',
        mail: `john.smith@${process.env.LDAP_SEED_EMAIL_DOMAIN ?? process.env.LDAP_DOMAIN ?? 'example.org'}`,
        userPassword: hashPassword(password),
        uidNumber: String(baseUid + 2),
        gidNumber: String(defaultGroup.gidNumber),
        homeDirectory: '/home/jsmith',
        loginShell: defaultShell
      },
      isAdmin: false,
      seedPassword: password
    },
    ...generateRandomUsers({
      baseDnUsers: USERS_OU_DN,
      baseUid,
      gidNumber: defaultGroup.gidNumber,
      defaultShell
    })
  ];

  const shouldLogCredentials = (() => {
    if (process.env.LDAP_SEED_LOG_CREDENTIALS != null) return isTruthy(process.env.LDAP_SEED_LOG_CREDENTIALS);
    return process.env.NODE_ENV !== 'production';
  })();

  if (shouldLogCredentials) {
    const credentials = users.map((u) => {
      const uid = u?.attributes?.uid;
      const mail = u?.attributes?.mail;
      return {
        uid,
        mail,
        password: u?.seedPassword,
        isAdmin: !!u?.isAdmin
      };
    }).filter((x) => x.uid);

    console.log('LDAP seed users (uid/password):');
    credentials.forEach((c) => {
      console.log(`- ${c.uid} | ${c.password} | ${c.mail}${c.isAdmin ? ' | admin' : ''}`);
    });
  }

  for (const user of users) {
    // Optionally seed SSH public key from env
    try {
      const uid = user.attributes.uid;
      const specificVar = `LDAP_SEED_SSH_PUBLIC_KEY_${String(uid ?? '').toUpperCase()}`;
      const seedKey = process.env[specificVar] ?? process.env.LDAP_SEED_SSH_PUBLIC_KEY;
      if (seedKey && !user.attributes.sshPublicKey) {
        user.attributes.sshPublicKey = seedKey;
      }
    } catch {}

    try {
      let existed = false;
      await new Promise((resolve, reject) => {
        client.add(user.dn, user.attributes, (err) => {
          if (err && err.code !== 68) { // 68 = Entry Already Exists
            reject(err);
          } else {
            if (err && err.code === 68) {
              existed = true;
              console.log(`User already exists: ${user.dn}`);
            } else {
              console.log(`Created user: ${user.dn}`);
            }
            resolve();
          }
        });
      });

      // If the user existed, ensure required POSIX and SSH classes/attrs are present
      if (existed) {
        // Fetch current attributes
        const current = await new Promise((resolve, reject) => {
          client.search(user.dn, { scope: 'base', attributes: ['objectClass','uidNumber','gidNumber','homeDirectory','loginShell'] }, (err, res) => {
            if (err) return reject(err);
            let entryObj = null;
            res.on('searchEntry', (entry) => { entryObj = entry.object; });
            res.on('error', (e) => reject(e));
            res.on('end', () => resolve(entryObj));
          });
        });

        const objClasses = Array.isArray(current?.objectClass) ? current.objectClass.map(String) : (current?.objectClass ? [String(current.objectClass)] : []);

        const mods = [];
        if (!objClasses.includes('posixAccount')) {
          mods.push(new ldap.Change({
            operation: 'add',
            modification: new ldap.Attribute({ type: 'objectClass', values: ['posixAccount'] })
          }));
        }
        if (!objClasses.includes('ldapPublicKey')) {
          mods.push(new ldap.Change({
            operation: 'add',
            modification: new ldap.Attribute({ type: 'objectClass', values: ['ldapPublicKey'] })
          }));
        }
        if (!current?.uidNumber) {
          mods.push(new ldap.Change({
            operation: 'add',
            modification: new ldap.Attribute({ type: 'uidNumber', values: [user.attributes.uidNumber] })
          }));
        }
        if (!current?.gidNumber) {
          mods.push(new ldap.Change({
            operation: 'add',
            modification: new ldap.Attribute({ type: 'gidNumber', values: [user.attributes.gidNumber] })
          }));
        }
        if (!current?.homeDirectory) {
          mods.push(new ldap.Change({
            operation: 'add',
            modification: new ldap.Attribute({ type: 'homeDirectory', values: [user.attributes.homeDirectory] })
          }));
        }
        if (!current?.loginShell) {
          mods.push(new ldap.Change({
            operation: 'add',
            modification: new ldap.Attribute({ type: 'loginShell', values: [user.attributes.loginShell] })
          }));
        }

        for (const change of mods) {
          await new Promise((resolve) => {
            client.modify(user.dn, change, (err) => {
              if (err && err.code !== 20) { // ignore 'Type or value exists'
                console.warn(`Modify warning on ${user.dn}: ${err.message}`);
              }
              resolve();
            });
          });
        }
      }

      // Add user to admin group if they are an admin
      if (user.isAdmin) {
        const change = new ldap.Change({
          operation: 'add',
          modification: new ldap.Attribute({
            type: 'member',
            values: [user.dn]
          })
        });

        try {
          await new Promise((resolve, reject) => {
            client.modify(adminGroupDN, change, (err) => {
              if (err && err.code !== 20) { // 20 = Type or value exists
                reject(err);
              } else {
                if (err && err.code === 20) {
                  console.log(`User ${user.dn} is already a member of ${adminGroupDN}`);
                } else {
                  console.log(`Added user ${user.dn} to group ${adminGroupDN}`);
                }
                resolve();
              }
            });
          });
        } catch (error) {
          console.error(`Error adding user ${user.dn} to admin group:`, error.message);
          throw error;
        }
      }
    } catch (error) {
      console.error(`Error creating user ${user.dn}:`, error.message);
      throw error;
    }
  }
}

/**
 * Main function to initialize LDAP
 */
async function main() {
  let client;
  
  try {
    // Wait for LDAP server to be ready
    await waitForLdap(process.env.LDAP_URL);
    
    // Create LDAP client
    client = ldap.createClient({
      url: process.env.LDAP_URL,
      tlsOptions: {
        rejectUnauthorized: process.env.NODE_ENV !== 'development'
      },
      reconnect: true,
      timeout: 10000,
      connectTimeout: 10000
    });
    
    // Bind to LDAP
    await new Promise((resolve, reject) => {
      client.bind(process.env.LDAP_ADMIN_DN, process.env.LDAP_ADMIN_PASSWORD, (err) => {
        if (err) {
          reject(new Error(`LDAP bind failed: ${err.message}`));
        } else {
          console.log('Successfully bound to LDAP server');
          resolve();
        }
      });
    });
    
    // Skip schema check as it requires special permissions
    console.log('Skipping schema check as it requires special permissions');
    
    // Ensure organizational structure exists
    await ensureOrganizationalUnits(client);
    
    // Ensure admin group exists
    const adminGroupDN = await ensureAdminGroup(client);

    // Ensure default posix group exists
    const defaultGroup = await ensureDefaultPosixGroup(client);
    
    // Create users and add to admin group (and set posixAccount attrs)
    await ensureUsers(client, adminGroupDN, defaultGroup);
    
    console.log('LDAP initialization completed successfully');
    
  } catch (error) {
    console.error('LDAP initialization failed:', error);
    process.exit(1);
  } finally {
    if (client) {
      try {
        await new Promise((resolve) => {
          client.unbind(() => {
            client.destroy();
            resolve();
          });
        });
      } catch (e) {
        console.error('Error disconnecting from LDAP:', e);
      }
    }
  }
}

// Run the main function
main().catch(err => {
  console.error('Error in LDAP seed script:', err);
  process.exit(1);
});

// Export functions for testing
export {
  hashPassword,
  waitForLdap,
  checkLdapSchema,
  ensureOrganizationalUnits,
  ensureAdminGroup,
  ensureDefaultPosixGroup,
  ensureUsers,
  main
};

