import { Client } from 'ldapts';
import LdapStrategy from 'passport-ldapauth';
import crypto from 'crypto';
const { createHash } = crypto;
import { createUserWithRole } from '../db/userOps.js';
// Supported hash algorithms
const SUPPORTED_HASHES = ['{CRYPT}', '{SHA}', '{SSHA}'];

/**
 * Verify a password against various LDAP password hashes
 * @param {string} password - The password to verify
 * @param {string} storedHash - The stored hash with algorithm prefix
 * @returns {boolean} True if the password matches the hash
 */
function verifyPassword(password, storedHash) {
  if (!storedHash) return false;
  
  const startTime = Date.now();
  let result = false;
  
  // Handle different hash types
  if (storedHash.startsWith('{SSHA}')) {
    console.log('[Password Verify] Using SSHA (SHA1) verification');
    result = verifySaltedHash(password, storedHash);
  } else if (storedHash.startsWith('{SHA}')) {
    console.log('[Password Verify] Using SHA1 verification');
    result = verifyUnsaltedHash(password, storedHash);
  } else if (storedHash.startsWith('{CRYPT}')) {
    console.log('[Password Verify] Using CRYPT verification');
    // For crypt, we need to extract the salt from the stored hash
    const hashPart = storedHash.substring(7); // Remove {CRYPT}
    result = crypto.timingSafeEqual(
      Buffer.from(hashPart),
      Buffer.from(crypto.createHash('sha1').update(password).digest('hex'))
    );
  } else {
    // Try to verify as plain text (not recommended, only for testing)
    console.warn('[Password Verify] No supported hash prefix found, using plain text comparison (not recommended)');
    result = crypto.timingSafeEqual(
      Buffer.from(storedHash),
      Buffer.from(password)
    );
  }
  
  const duration = Date.now() - startTime;
  console.log(`[Password Verify] Verification took ${duration}ms`);
  
  return result;
}

/**
 * Verifies a password against a stored hash
 * @param {string} password - The password to verify
 * @param {string} storedHash - The stored hash to verify against
 * @returns {boolean} True if the password matches the hash
 */
function verifyPasswordHash(password, storedHash) {
  console.log('[Password Verify] Starting password verification');
  console.log(`[Password Verify] Hash type: ${storedHash.split('}')[0].substring(1) || 'PLAINTEXT'}`);
  
  if (typeof storedHash !== 'string') {
    console.error('[Password Verify] Invalid stored hash - not a string');
    return false;
  }

  if (!password) {
    console.error('[Password Verify] No password provided');
    return false;
  }

  try {
    let result = false;
    const startTime = Date.now();
    
    // Handle different hash types
    if (storedHash.startsWith('{SSHA}')) {
      console.log('[Password Verify] Using SSHA (SHA1) verification');
      result = verifySaltedHash(password, storedHash);
    } else if (storedHash.startsWith('{SHA}')) {
      console.log('[Password Verify] Using SHA1 verification');
      result = verifyUnsaltedHash(password, storedHash);
    } else if (storedHash.startsWith('{CRYPT}')) {
      console.log('[Password Verify] Using CRYPT verification');
      // For crypt, we need to extract the salt from the stored hash
      const hashPart = storedHash.substring(7); // Remove {CRYPT}
      result = crypto.timingSafeEqual(
        Buffer.from(hashPart),
        Buffer.from(crypto.createHash('sha1').update(password).digest('hex'))
      );
    } else {
      // Try to verify as plain text (not recommended, only for testing)
      console.warn('[Password Verify] No supported hash prefix found, using plain text comparison (not recommended)');
      result = crypto.timingSafeEqual(
        Buffer.from(storedHash),
        Buffer.from(password)
      );
    }
    
    const duration = Date.now() - startTime;
    console.log(`[Password Verify] Verification ${result ? 'succeeded' : 'failed'} in ${duration}ms`);
    return result;
    
  } catch (error) {
    console.error('[Password Verify] Error during verification:', error);
    return false;
  }
}

/**
 * Hash a password using the specified scheme
 * @param {string} password - The password to hash
 * @param {string} scheme - The hashing scheme to use (CRYPT, SHA, SSHA)
 * @returns {string} The hashed password
 */
function hashPassword(password, scheme = '{SSHA}') {
  if (!SUPPORTED_HASHES.includes(scheme)) {
    throw new Error(`Unsupported hash scheme: ${scheme}. Supported: ${SUPPORTED_HASHES.join(', ')}`);
  }

  if (scheme === '{CRYPT}') {
    // Simple SHA-1 hash for CRYPT (not secure, but matches the verify function above)
    return `{CRYPT}${crypto.createHash('sha1').update(password).digest('hex')}`;
  } else if (scheme === '{SHA}') {
    // Unsalted SHA-1
    const hash = crypto.createHash('sha1')
      .update(password, 'utf8')
      .digest('base64');
    return `{SHA}${hash}`;
  } else if (scheme === '{SSHA}') {
    // Salted SHA-1
    const salt = crypto.randomBytes(8);
    const hash = crypto.createHash('sha1')
      .update(password, 'utf8')
      .update(salt)
      .digest();
    const ssha = Buffer.concat([hash, salt]).toString('base64');
    return `{SSHA}${ssha}`;
  }
  
  throw new Error(`Unsupported hash scheme: ${scheme}`);
}

/**
 * Verifies a password against a salted hash (SSHA)
 * @param {string} password - The password to verify
 * @param {string} storedHash - The stored hash with algorithm prefix
 * @returns {boolean} True if the password matches the hash
 */
function verifySaltedHash(password, storedHash) {
  try {
    // Extract the hash type (should be SSHA)
    const hashType = storedHash.match(/^{([^}]+)}/)[1];
    console.log(`[verifySaltedHash] Hash type: ${hashType}`);
    
    if (hashType !== 'SSHA') {
      console.error(`[verifySaltedHash] Unsupported hash type: ${hashType}`);
      return false;
    }
    
    // Get the base64 part after the algorithm
    const base64Hash = storedHash.substring(hashType.length + 2); // +2 for { and }
    const hashBuffer = Buffer.from(base64Hash, 'base64');
    
    // For SSHA, the hash is the first 20 bytes, the salt is the rest
    const hashLength = 20; // SHA-1 is 20 bytes
    const hash = hashBuffer.slice(0, hashLength);
    const salt = hashBuffer.slice(hashLength);
    
    // Recompute the hash
    const computedHash = crypto.createHash('sha1')
      .update(Buffer.from(password, 'utf8'))
      .update(salt)
      .digest();
    
    // Compare the hashes
    return crypto.timingSafeEqual(hash, computedHash);
  } catch (error) {
    console.error('[verifySaltedHash] Error:', error);
    return false;
  }
}

/**
 * Verifies a password against an unsalted hash (SHA)
 * @param {string} password - The password to verify
 * @param {string} storedHash - The stored hash with algorithm prefix
 * @returns {boolean} True if the password matches the hash
 */
function verifyUnsaltedHash(password, storedHash) {
  try {
    // Extract the hash type (should be SHA)
    const hashType = storedHash.match(/^{([^}]+)}/)[1];
    console.log(`[verifyUnsaltedHash] Hash type: ${hashType}`);
    
    if (hashType !== 'SHA') {
      console.error(`[verifyUnsaltedHash] Unsupported hash type: ${hashType}`);
      return false;
    }
    
    // Get the base64 part after the algorithm
    const base64Hash = storedHash.substring(hashType.length + 2); // +2 for { and }
    const hashBuffer = Buffer.from(base64Hash, 'base64');
    
    // Recompute the hash
    const computedHash = crypto.createHash('sha1')
      .update(Buffer.from(password, 'utf8'))
      .digest();
    
    // Compare the hashes
    return crypto.timingSafeEqual(hashBuffer, computedHash);
  } catch (error) {
    console.error('[verifyUnsaltedHash] Error:', error);
    return false;
  }
}

/**
 * Check LDAP user credentials using direct bind
 * @param {string} username - The username to check
 * @param {string} password - The password to verify
 * @returns {Promise<Object|null>} User object if valid, null otherwise
 */
async function checkLdapUser(username, password) {
  if (!username || !password) {
    console.error('[LDAP Auth] Missing username or password');
    return null;
  }

  try {
    // First, search for the user to get their DN and stored hash
    const user = await findLdapUser(username);
    if (!user) {
      console.error(`[LDAP Auth] User not found: ${username}`);
      return null;
    }

    // Try to bind as the user to verify credentials
    try {
      const userClient = new Client({
        url: process.env.LDAP_URL,
        tlsOptions: process.env.LDAP_TLS_REJECT_UNAUTHORIZED === 'false' ? {
          rejectUnauthorized: false
        } : undefined
      });

      // Attempt to bind with the user's DN and password
      await userClient.bind(user.dn, password);
      await userClient.unbind();
      
      console.log(`[LDAP Auth] Successfully authenticated user: ${username}`);
      
      // Return user information
      return {
        id: user.uid || username,
        username: user.uid || username,
        displayName: user.displayName || user.cn || username,
        email: user.mail,
        memberOf: user.memberOf || [],
        raw: user
      };
      
    } catch (bindError) {
      console.error(`[LDAP Auth] Invalid credentials for user: ${username}`, bindError.message);
      return null;
    }
    
  } catch (error) {
    console.error('[LDAP Auth] Error during LDAP user check:', error);
    throw error;
  }
}

/**
 * Find an LDAP user by username
 * @param {string} username - The username to find
 * @returns {Promise<Object|null>} The user object or null if not found
 */
async function findLdapUser(username) {
  const client = new Client({
    url: process.env.LDAP_URL,
    tlsOptions: process.env.LDAP_TLS_REJECT_UNAUTHORIZED === 'false' ? {
      rejectUnauthorized: false
    } : undefined,
    timeout: 5000, // 5 second timeout
    connectTimeout: 5000 // 5 second connect timeout
  });
  
  try {
    const searchBase = process.env.LDAP_SEARCH_BASE_USERS || 'ou=users,dc=example,dc=org';
    // Escape special characters in username for LDAP filter
    const escapedUsername = username.replace(/[\\*()\0\x00]/g, char => `\\${char.charCodeAt(0).toString(16).padStart(2, '0')}`);
    // Use the filter from env or default to uid filter, and ensure we replace any template variables
    const filterTemplate = process.env.LDAP_SEARCH_FILTER || '(uid={{username}})';
    const searchFilter = filterTemplate.replace('{{username}}', escapedUsername);
    
    // First try to bind with admin credentials to search
    try {
      await client.bind(
        process.env.LDAP_ADMIN_DN,
        process.env.LDAP_ADMIN_PASSWORD
      );
      
      const { searchEntries } = await client.search(searchBase, {
        scope: 'sub',
        filter: searchFilter,
        attributes: ['*', '+', 'userPassword']
      });

      if (!searchEntries || searchEntries.length === 0) {
        console.log(`[findLdapUser] No user found matching filter: ${searchFilter}`);
        return null;
      }

      console.log(`[findLdapUser] Found user: ${searchEntries[0].dn}`);
      return searchEntries[0];
    } catch (searchError) {
      console.error('[findLdapUser] Error searching for user:', searchError);
      throw searchError;
    }
  } catch (error) {
    console.error('[findLdapUser] Error:', error);
    throw error;
  } finally {
    try {
      await client.unbind();
    } catch (e) {
      console.error('[findLdapUser] Error during LDAP unbind:', e);
    }
  }
}

/**
 * Change a user's password in LDAP
 * @param {string} username - The username
 * @param {string} oldPassword - The current password
 * @param {string} newPassword - The new password
 * @param {string} [hashScheme='{SSHA}'] - The hashing scheme to use
 * @returns {Promise<boolean>} True if successful
 */
async function changeLdapPassword(username, oldPassword, newPassword, hashScheme = '{SSHA}') {
  if (!SUPPORTED_HASHES.includes(hashScheme)) {
    throw new Error(`Unsupported hash scheme: ${hashScheme}. Supported: ${SUPPORTED_HASHES.join(', ')}`);
  }

  // First, verify the old password
  const user = await findLdapUser(username);
  if (!user) {
    throw new Error('User not found');
  }

  // Create a client bound as the user to verify old password
  const userClient = new Client({
    url: process.env.LDAP_URL,
    tlsOptions: process.env.LDAP_TLS_REJECT_UNAUTHORIZED === 'false' ? {
      rejectUnauthorized: false
    } : undefined
  });

  try {
    // Verify old password by binding as the user
    await userClient.bind(user.dn, oldPassword);
    
    // Hash the new password
    const newHashedPassword = hashPassword(newPassword, hashScheme);
    
    // Update the password
    await userClient.modify(user.dn, {
      operation: 'replace',
      modification: {
        userPassword: newHashedPassword
      }
    });
    
    return true;
  } catch (error) {
    console.error('Failed to change password:', error);
    throw error;
  } finally {
    try {
      await userClient.unbind();
    } catch (e) {
      console.error('Error during LDAP unbind:', e);
    }
  }
}

// Create a single instance to be used across the application
const ldapClient = new Client({
  url: process.env.LDAP_URL,
  tlsOptions: process.env.LDAP_TLS_REJECT_UNAUTHORIZED === 'false' ? {
    rejectUnauthorized: false
  } : undefined
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  try {
    await ldapClient.unbind();
    console.log('LDAP client disconnected through app termination');
    process.exit(0);
  } catch (error) {
    console.error('Error during LDAP client shutdown:', error);
    process.exit(1);
  }
});

function getLdapConfig() {
  // Validate required environment variables
  const requiredVars = [
    'LDAP_URL',
    'LDAP_ADMIN_DN',
    'LDAP_ADMIN_PASSWORD',
    'LDAP_SEARCH_BASE_USERS'
  ];
  
  const missingVars = requiredVars.filter(varName => !process.env[varName]);
  if (missingVars.length > 0) {
    throw new Error(`Missing required LDAP environment variables: ${missingVars.join(', ')}`);
  }

  // Create the LDAP configuration object
  const config = {
    server: {
      url: process.env.LDAP_URL,
      bindDN: process.env.LDAP_ADMIN_DN,
      bindCredentials: process.env.LDAP_ADMIN_PASSWORD,
      searchBase: process.env.LDAP_SEARCH_BASE_USERS || 'ou=users,dc=example,dc=org',
      searchFilter: process.env.LDAP_SEARCH_FILTER || '(uid={{username}})',
      searchAttributes: ['uid', 'cn', 'mail', 'givenName', 'sn', 'displayName', 'userPassword'],
      searchScope: 'sub',  // Search the entire subtree
      tlsOptions: process.env.LDAP_TLS_REJECT_UNAUTHORIZED === 'false' ? {
        rejectUnauthorized: false
      } : undefined,
      
      // Enable direct user binding
      bindProperty: 'dn',
      
      // Use simple authentication
      authentication: 'simple',
      
      // Disable anonymous bind
      allowAnonymous: false,
      
      // Additional LDAP options
      includeRaw: true,
      groupSearchBase: 'ou=groups,dc=example,dc=org',
      groupSearchFilter: '(member={{dn}})',
      groupSearchAttributes: ['dn', 'cn'],
      groupDnProperty: 'dn',
      groupSearchScope: 'sub'
    },
    usernameField: 'username',
    passwordField: 'password',
    session: false,
    passReqToCallback: true,
    includeRaw: true,
    
    // Custom verify function that will be called after successful LDAP authentication
    verify: async function(req, user, done) {
      console.log('[LDAP] Custom verify function called');
      const username = user.uid || user.sAMAccountName || user.cn || user.username;
      
      if (!username) {
        console.error('No username found in LDAP response');
        return done(null, false, { message: 'No username found in LDAP response' });
      }
      
      try {
        // Determine admin status through group search
        const adminGroupCN = (process.env.LDAP_APP_ADMIN_GROUP_CN || process.env.LDAP_ADMIN_GROUP_CN || 'admin').toLowerCase();
        const isAdmin = await isUserInAdminGroup(username, adminGroupCN);
        
        // Create a normalized user object with required properties
        const normalizedUser = {
          id: user.uid || user.sAMAccountName || user.cn || user.username,
          username: username,
          displayName: user.displayName || user.cn || user.uid || 'Unknown User',
          email: user.mail || `${username}@${process.env.EMAIL_DOMAIN || 'example.com'}`,
          isAdmin: isAdmin,
          raw: user // Keep the raw LDAP user data
        };
        
        console.log(`[LDAP] Successfully authenticated user: ${username}`, {
          adminGroupCN,
          isAdmin
        });
        
        return done(null, normalizedUser);
      } catch (error) {
        console.error('[LDAP] Error in verify function:', error);
        return done(error);
      }
    }
  };
  
  return config;
}

/**
 * Configure LDAP authentication using Passport
 * @param {Object} passport - Passport instance
 * @returns {Object} The configured LDAP strategy
 */
function configureLdapAuth(passport) {
  if (!passport) {
    throw new Error('Passport instance is required');
  }

  console.log('Configuring LDAP authentication...');
  
  try {
    const config = getLdapConfig();
    
    // Create the LDAP strategy with our custom configuration
    const strategy = new LdapStrategy(config, async (req, user, done) => {
      try {
        //console.log('LDAP Auth - User object from LDAP:', JSON.stringify(user, null, 2));
        
        // Check if user object is valid
        if (!user) {
          console.error('[LDAP Auth] No user object returned from LDAP');
          return done(null, false, { message: 'Invalid credentials' });
        }
        
        // Get admin group CN from environment
        const adminGroupCN = process.env.LDAP_APP_ADMIN_GROUP_CN;
        
        console.log(`[LDAP Auth] Checking admin group membership for user: ${user.dn}`);
        
        let isAdmin = false;
        
        try {
          // Use the centralized isUserInAdminGroup function
          isAdmin = await isUserInAdminGroup(user.uid || user.username);
          console.log(`[LDAP Auth] User ${user.uid || user.username} is ${isAdmin ? '' : 'not '}an admin`);
        } catch (error) {
          console.error('[LDAP Auth] Error checking admin group membership:', error);
          isAdmin = false;
          console.log(`[LDAP Auth] Defaulting to non-admin due to error for user: ${user.username}`);
        }
          
        // Create a normalized user object with required properties
        const normalizedUser = {
          id: user.uid || user.sAMAccountName || user.cn || user.username,
          username: user.uid || user.sAMAccountName || user.cn || user.username,
          displayName: user.displayName || user.cn || user.uid || 'Unknown User',
          email: user.mail || `${user.uid}@${process.env.EMAIL_DOMAIN || 'example.com'}`,
          isAdmin: isAdmin,
          raw: user // Keep the raw LDAP user data
        };
        
        if (!normalizedUser.username) {
          console.error('[LDAP Auth] Could not determine username from LDAP response');
          return done(null, false, { message: 'Could not determine username' });
        }
        
        try {
          // Create or update the user in the database
          const userId = await createUserWithRole({
            username: normalizedUser.username,
            email: normalizedUser.email,
            displayName: normalizedUser.displayName,
            roleName: isAdmin ? 'admin' : 'user'
          });
          
          // Update the user ID with the one from the database
          normalizedUser.id = userId;
          console.log(`[LDAP Auth] Successfully synced user to database: ${normalizedUser.username} (ID: ${userId})`);
          
        } catch (dbError) {
          console.error('[LDAP Auth] Error syncing user to database:', dbError);
          // Continue with login even if DB sync fails, but log the error
        }
        
        // Log successful authentication
        console.log(`[LDAP Auth] Successfully authenticated user: ${normalizedUser.username}`);
        
        // Return the normalized user object with database ID
        return done(null, normalizedUser);
        
      } catch (error) {
        console.error('[LDAP Auth] Error in verify callback:', error);
        return done(error);
      }
    });
    
    // Add error handler for the strategy
    strategy.error = function(err) {
      console.error('[LDAP Auth] Strategy error:', err);
    };
    
    // Use the strategy with passport
    passport.use('ldapauth', strategy);
    console.log('LDAP authentication strategy configured successfully');
    
    return strategy;
    
  } catch (error) {
    console.error('Error configuring LDAP authentication:', error);
    throw error;
  }
}

/**
 * Checks if a password meets LDAP password policy requirements
 * @param {string} password - The password to check
 * @returns {Promise<{valid: boolean, message?: string}>} Object with validation result and optional message
 */
async function checkPasswordPolicy(password) {
  // Default policy (can be overridden by LDAP server policy)
  const defaultPolicy = {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    specialChars: '!@#$%^&*()_+\-={}[]|:;\"<>,.?/~`',
    maxConsecutiveRepeats: 3,
    maxSequenceLength: 4
  };

  // Check minimum length
  if (password.length < defaultPolicy.minLength) {
    return { 
      valid: false, 
      message: `Password must be at least ${defaultPolicy.minLength} characters long` 
    };
  }

  // Check for uppercase letters
  if (defaultPolicy.requireUppercase && !/[A-Z]/.test(password)) {
    return { 
      valid: false, 
      message: 'Password must contain at least one uppercase letter' 
    };
  }

  // Check for lowercase letters
  if (defaultPolicy.requireLowercase && !/[a-z]/.test(password)) {
    return { 
      valid: false, 
      message: 'Password must contain at least one lowercase letter' 
    };
  }

  // Check for numbers
  if (defaultPolicy.requireNumbers && !/\d/.test(password)) {
    return { 
      valid: false, 
      message: 'Password must contain at least one number' 
    };
  }

  // Check for special characters
  if (defaultPolicy.requireSpecialChars && 
      !new RegExp(`[${defaultPolicy.specialChars.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}]`).test(password)) {
    return { 
      valid: false, 
      message: `Password must contain at least one special character (${defaultPolicy.specialChars})` 
    };
  }

  // Check for consecutive repeated characters
  if (defaultPolicy.maxConsecutiveRepeats) {
    const repeatRegex = new RegExp(`(.)\\1{${defaultPolicy.maxConsecutiveRepeats - 1},}`); 
    if (repeatRegex.test(password)) {
      return {
        valid: false,
        message: `Password contains too many repeated characters (max ${defaultPolicy.maxConsecutiveRepeats - 1} allowed)`
      };
    }
  }

  // Check for sequential characters (e.g., '1234' or 'abcd')
  if (defaultPolicy.maxSequenceLength) {
    let sequence = 0;
    let lastCharCode = 0;
    
    for (let i = 0; i < password.length; i++) {
      const charCode = password.charCodeAt(i);
      if (charCode === lastCharCode + 1) {
        sequence++;
        if (sequence >= defaultPolicy.maxSequenceLength - 1) {
          return {
            valid: false,
            message: 'Password contains a sequence of characters that is too long'
          };
        }
      } else {
        sequence = 0;
      }
      lastCharCode = charCode;
    }
  }

    // TODO: Add LDAP server password policy check here
  // This would involve querying the LDAP server's password policy control
  // and validating according to the server's specific requirements

  return { valid: true };
}

/**
 * Checks if a user is a member of the admin group
 * @param {string} username - The username to check
 * @returns {Promise<boolean>} True if the user is in the admin group
 */
async function isUserInAdminGroup(username) {
  if (!username) return false;
  
  try {
    const user = await findLdapUser(username);
    if (!user) {
      console.error(`[Admin Check] User ${username} not found in LDAP`);
      return false;
    }

    // Get admin group CN and base DN from environment
    const adminGroupCN = process.env.LDAP_APP_ADMIN_GROUP_CN;
    const groupsBaseDN = process.env.LDAP_SEARCH_BASE_GROUPS;
    
    if (!adminGroupCN || !groupsBaseDN) {
      console.error('[Admin Check] Missing required environment variables: LDAP_APP_ADMIN_GROUP_CN or LDAP_SEARCH_BASE_GROUPS');
      return false;
    }

    // Search for the user's groups to check admin membership
    try {
      console.log(`[Admin Check] Checking if user ${username} is in admin group ${adminGroupCN}`);
      
      // Create a new client with admin credentials for the search
      const adminClient = new Client({
        url: process.env.LDAP_URL,
        tlsOptions: process.env.LDAP_TLS_REJECT_UNAUTHORIZED === 'false' ? {
          rejectUnauthorized: false
        } : undefined,
        timeout: 5000,
        connectTimeout: 5000
      });
      
      try {
        // Bind with admin credentials
        await adminClient.bind(
          process.env.LDAP_ADMIN_DN,
          process.env.LDAP_ADMIN_PASSWORD
        );
        
        console.log(`[Admin Check] Successfully bound as admin: ${process.env.LDAP_ADMIN_DN}`);
        
        // Search for the admin group and check if the user is a member
        const searchFilter = `(&(objectClass=groupOfNames)(cn=${adminGroupCN})(member=${user.dn}))`;
        
        const { searchEntries } = await adminClient.search(groupsBaseDN, {
          scope: 'sub',
          filter: searchFilter,
          attributes: ['cn']
        });
        
        // If we found the admin group with this user as a member, they're an admin
        const isAdmin = searchEntries.length > 0;
        console.log(`[Admin Check] User ${username} is ${isAdmin ? 'an admin' : 'not an admin'}`);
        return isAdmin;
      
      } finally {
        // Always unbind the admin client
        await adminClient.unbind().catch(e => 
          console.error('[Admin Check] Error unbinding admin client:', e)
        );
      }
    } catch (searchError) {
      console.error('[Admin Check] Error searching for admin group:', searchError);
      return false;
    }
  } catch (error) {
    console.error('Error in isUserInAdminGroup:', error);
    return false;
  }
}

// Export the LDAP client and utility functions
export {
  configureLdapAuth,
  ldapClient,
  checkLdapUser,
  findLdapUser,
  changeLdapPassword,
  verifyPassword,
  hashPassword,
  checkPasswordPolicy,
  isUserInAdminGroup,
  SUPPORTED_HASHES,
  getLdapConfig
};
