import pool from './index.js';
import { ldapClient as ldapClientInstance } from '../utils/ldapClient.js';
import { Change, Attribute } from 'ldapts';
import { getUserById } from './userOps.js';
import { detectKeyTypeFromCOSE, coseToOpenSSHFidoPub } from '../utils/sshKeys.js';
import cbor from 'cbor';
import crypto from 'crypto';
import { logger } from '../utils/logger.js';

// Helper functions for COSE key information
function getKeyTypeName(kty) {
  const keyTypes = {
    1: 'OKP (Octet Key Pair)',
    2: 'EC2 (Elliptic Curve)',
    3: 'RSA',
    4: 'Symmetric',
  };
  return keyTypes[kty] || `Unknown (${kty})`;
}

/**
 * Update SSH-related metadata for an authenticator
 * @param {number} id - Authenticator ID
 * @param {{ ssh_key_type?: string, ssh_comment?: string }} meta
 * @returns {Promise<object>} Updated authenticator row
 */
async function updateAuthenticatorSSHMetadata(id, meta = {}) {
  const client = await pool.connect();
  try {
    const fields = [];
    const values = [];
    let i = 1;

    if (meta.ssh_key_type !== undefined) {
      fields.push(`ssh_key_type = $${i++}`);
      values.push(meta.ssh_key_type);
    }
    if (meta.ssh_comment !== undefined) {
      fields.push(`ssh_comment = $${i++}`);
      values.push(meta.ssh_comment);
    }
    // Always set uploaded_at when we touch SSH metadata
    fields.push(`ssh_uploaded_at = NOW()`);
    fields.push(`updated_at = NOW()`);

    if (fields.length === 0) {
      throw new AuthenticatorError('No SSH metadata to update', 'NO_SSH_METADATA');
    }

    values.push(id);
    const sql = `UPDATE authenticators SET ${fields.join(', ')} WHERE id = $${i}::uuid RETURNING *`;
    const result = await client.query(sql, values);
    if (result.rows.length === 0) {
      throw new AuthenticatorError('Authenticator not found', 'AUTHENTICATOR_NOT_FOUND');
    }
    const row = result.rows[0];
    row.user_id = row.user_id?.toString?.() || row.user_id;
    return row;
  } catch (e) {
    console.error('Error updating SSH metadata:', e);
    if (e instanceof AuthenticatorError) throw e;
    throw new AuthenticatorError('Failed to update SSH metadata', 'SSH_METADATA_UPDATE_FAILED');
  } finally {
    client.release();
  }
}

function getAlgorithmName(alg) {
  // Using computed property names for negative numbers
  const algorithms = {};
  
  // ECDSA algorithms
  algorithms[-7] = 'ES256 (ECDSA w/ SHA-256)';
  algorithms[-35] = 'ES384 (ECDSA w/ SHA-384)';
  algorithms[-36] = 'ES512 (ECDSA w/ SHA-512)';
  
  // EdDSA algorithms
  algorithms[-8] = 'EdDSA';
  
  // RSASSA-PKCS1-v1_5 algorithms
  algorithms[-257] = 'RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)';
  algorithms[-258] = 'RS384 (RSASSA-PKCS1-v1_5 w/ SHA-384)';
  algorithms[-259] = 'RS512 (RSASSA-PKCS1-v1_5 w/ SHA-512)';
  
  // RSASSA-PSS algorithms
  algorithms[-37] = 'PS256 (RSASSA-PSS w/ SHA-256)';
  algorithms[-38] = 'PS384 (RSASSA-PSS w/ SHA-384)';
  algorithms[-39] = 'PS512 (RSASSA-PSS w/ SHA-512)';
  
  return algorithms[alg] || `Unknown (${alg})`;
}

// ASN.1 encoding helpers
const ASN1 = {
  SEQUENCE: 0x30,
  BIT_STRING: 0x03,
  OBJECT_IDENTIFIER: 0x06,
  OID_EC_PUBLIC_KEY: [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01], // 1.2.840.10045.2.1
  OID_PRIME256V1: [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], // 1.2.840.10045.3.1.7
  
  toLengthBytes: function(length) {
    if (length < 0x80) {
      return [length];
    }
    const bytes = [];
    while (length > 0) {
      bytes.unshift(length & 0xFF);
      length = length >>> 8;
    }
    return [0x80 + bytes.length, ...bytes];
  },
  
  encodeOID: function(oid) {
    const bytes = [];
    bytes.push(oid[0] * 40 + oid[1]);
    
    for (let i = 2; i < oid.length; i++) {
      let value = oid[i];
      if (value < 128) {
        bytes.push(value);
      } else {
        const temp = [value & 0x7F];
        value = value >>> 7;
        while (value > 0) {
          temp.unshift((value & 0x7F) | 0x80);
          value = value >>> 7;
        }
        bytes.push(...temp);
      }
    }
    
    const lengthBytes = this.toLengthBytes(bytes.length);
    return [this.OBJECT_IDENTIFIER, ...lengthBytes, ...bytes];
  },
  
  encodeSequence: function(components) {
    const content = [];
    for (const component of components) {
      content.push(...component);
    }
    const lengthBytes = this.toLengthBytes(content.length);
    return [this.SEQUENCE, ...lengthBytes, ...content];
  },
  
  encodeBitString: function(bytes) {
    const content = [0x00, ...bytes]; // Add unused bits byte (0x00)
    const lengthBytes = this.toLengthBytes(content.length);
    return [this.BIT_STRING, ...lengthBytes, ...content];
  }
};

/**
 * Process and validate a COSE public key for WebAuthn
 * @param {Buffer|Uint8Array} publicKey - The COSE public key to process
 * @returns {Object} Processed public key information
 * @property {Buffer} publicKeyBuffer - The original COSE key buffer
 * @property {string} publicKeyHex - Hex representation of the COSE key
 * @property {string} publicKeyPEM - PEM representation (for backward compatibility)
 */
function processPublicKey(publicKey) {
  let publicKeyBuffer;
  
  // Convert to Buffer if needed
  if (Buffer.isBuffer(publicKey)) {
    publicKeyBuffer = publicKey;
  } else if (publicKey instanceof Uint8Array) {
    publicKeyBuffer = Buffer.from(publicKey);
  } else {
    throw new Error('Unsupported public key format. Expected Buffer or Uint8Array.');
  }
  
  // Parse the COSE key to validate its structure
  let coseKey;
  try {
    coseKey = cbor.decodeFirstSync(publicKeyBuffer);
  } catch (err) {
    console.error('Error decoding COSE key:', err);
    throw new Error('Invalid COSE public key format: ' + err.message);
  }
  
  // Validate COSE key format for EC2 (Elliptic Curve)
  if (coseKey.get(1) !== 2) { // kty: 2 = EC2
    throw new Error(`Unsupported key type: ${coseKey.get(1)}. Expected EC2 (2).`);
  }
  
  if (coseKey.get(3) !== -7) { // alg: -7 = ES256
    console.warn(`Warning: Expected algorithm ES256 (-7), got ${coseKey.get(3)}`);
  }
  
  if (coseKey.get(-1) !== 1) { // crv: 1 = P-256
    throw new Error(`Unsupported curve: ${coseKey.get(-1)}. Expected P-256 (1).`);
  }
  
  // Get x and y coordinates
  const x = coseKey.get(-2); // x-coordinate
  const y = coseKey.get(-3); // y-coordinate
  
  if (!x || !y) {
    throw new Error('Missing x or y coordinate in EC key');
  }
  
  // For backward compatibility, generate a minimal PEM representation
  // This is only used for logging and backward compatibility
  const publicKeyPEM = '-----BEGIN COSE PUBLIC KEY-----\n' +
    'Note: This is a COSE key in binary format. ' +
    'It should be processed by WebAuthn libraries.\n' +
    '-----END COSE PUBLIC KEY-----';
  
  return {
    publicKeyHex: publicKeyBuffer.toString('hex'),
    publicKeyBuffer: publicKeyBuffer,
    publicKeyPEM: publicKeyPEM
  };
}

class AuthenticatorError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'AuthenticatorError';
    this.code = code || 'AUTHENTICATOR_ERROR';
  }
}

/**
 * Save or update an authenticator for a user
 * @param {Object} params - Authenticator parameters
 * @param {number} params.userId - User ID
 * @param {Buffer} params.credentialID - The credential ID
 * @param {Buffer} params.credentialPublicKey - The public key
 * @param {string} [params.name='Security Key'] - Display name for the authenticator
 * @param {string[]} [params.transports=[]] - List of supported transports
 * @returns {Promise<Object>} The saved authenticator
 */
async function saveAuthenticator({
  userId,
  credentialID,
  credentialPublicKey,
  name = 'Security Key',
  transports = [],
  userDisplayName = null
}) {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Validate required parameters
    if (!credentialID) {
      throw new Error('credentialID is required');
    }
    if (!credentialPublicKey) {
      throw new Error('credentialPublicKey is required');
    }

    // Convert credential ID to hex string for storage
    let credentialIdHex;
    try {
      credentialIdHex = Buffer.isBuffer(credentialID) 
        ? credentialID.toString('hex')
        : credentialID.startsWith('0x') 
          ? credentialID.slice(2) // Remove 0x prefix if present
          : credentialID;
    } catch (error) {
      console.error('Error processing credential ID:', error);
      throw new Error('Invalid credential ID format');
    }

    // Process the public key for storage
    let publicKeyBuffer;
    if (Buffer.isBuffer(credentialPublicKey)) {
      publicKeyBuffer = credentialPublicKey;
    } else if (credentialPublicKey instanceof Uint8Array) {
      publicKeyBuffer = Buffer.from(credentialPublicKey);
    } else {
      throw new Error('credentialPublicKey must be a Buffer or Uint8Array');
    }
    
    // Validate it's a valid COSE key (tolerant: do not fail registration on decode error)
    try {
      const coseKey = cbor.decodeFirstSync(publicKeyBuffer);
      if (!coseKey || typeof coseKey.get !== 'function') {
        throw new Error('Invalid COSE key format');
      }
      // Optional: normalize to canonical encoding for consistent storage
      try {
        const normalized = cbor.encodeCanonical(coseKey);
        if (normalized && normalized.length > 0) {
          publicKeyBuffer = Buffer.from(normalized);
        }
      } catch {}

      // Log the COSE key structure for debugging
      logger.debug('[Database] COSE Key Structure:');
      logger.debug(`- Key Type: ${coseKey.get(1)} (${getKeyTypeName(coseKey.get(1))})`);
      logger.debug(`- Algorithm: ${coseKey.get(3)} (${getAlgorithmName(coseKey.get(3))})`);
      logger.debug(`- Curve: ${coseKey.get(-1) || 'N/A'}`);
      
    } catch (error) {
      // Be lenient: store the raw key and let verification path normalize/validate later
      console.warn('[Database] Warning: Could not decode COSE key during save. Storing as-is. Reason:', error?.message || error);
    }
    
    // First, check if the user already has an authenticator
    const existingAuth = await client.query(
      'SELECT id FROM authenticators WHERE user_id = $1::uuid',
      [userId]
    );
    
    let result;
    // If userDisplayName is provided, update the user's display name in the users table
    if (userDisplayName) {
      logger.debug(`Updating user ${userId} display name to:`, userDisplayName);
      await client.query(
        'UPDATE users SET display_name = $1 WHERE id = $2',
        [userDisplayName, userId]
      );
    }
    
    if (existingAuth.rows.length > 0) {
      // Update existing authenticator
      result = await client.query(
        `UPDATE authenticators 
         SET credential_id = $1, 
             credential_public_key = $2, 
             name = $3, 
             transports = $4,
             counter = 0,
             updated_at = NOW()
         WHERE user_id = $5::uuid
         RETURNING *`,
        [credentialIdHex, publicKeyBuffer, name, transports, userId]
      );
    } else {
      
      // Insert new authenticator
      result = await client.query(
        `INSERT INTO authenticators (
          user_id, 
          credential_id, 
          credential_public_key, 
          name, 
          transports,
          counter
        ) VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *`,
        [
          userId,
          credentialIdHex,
          publicKeyBuffer, // Use the binary buffer directly
          name,
          transports.length > 0 ? transports : ['internal'],
          0 // Initial counter
        ]
      );
    }
    
    await client.query('COMMIT');

    // Note: Storing userCertificate in LDAP is handled during registration using
    // the authenticator attestation certificate (x5c) to comply with RFC4523.
    // We do not store the COSE public key here.

    return result.rows[0];
  } catch (error) {
    await client.query('ROLLBACK');
    
    if (error.constraint === 'one_authenticator_per_user') {
      throw new AuthenticatorError('User already has an authenticator registered', 'AUTHENTICATOR_EXISTS');
    } else if (error.constraint === 'uq_credential_id') {
      throw new AuthenticatorError('Authenticator already registered', 'CREDENTIAL_EXISTS');
    }
    
    console.error('Error saving authenticator:', error);
    throw new AuthenticatorError('Failed to save authenticator');
  } finally {
    client.release();
  }
}

/**
 * Get an authenticator by user ID
 * @param {string} userId - User ID (UUID)
 * @returns {Promise<Object|null>} The authenticator or null if not found
 */
async function getAuthenticatorByUserId(userId) {
  try {
    logger.debug(`Fetching authenticator for user ID: ${userId}`);
    const result = await pool.query(
      'SELECT * FROM authenticators WHERE user_id = $1::uuid',
      [userId]
    );
    
    if (!result.rows[0]) {
      logger.debug('No authenticator found for user ID:', userId);
      return null;
    }
    
    const authenticator = { ...result.rows[0] };

    // Ensure user_id is a string
    authenticator.user_id = authenticator.user_id.toString();

    // Ensure credential_public_key is a Buffer
    if (authenticator.credential_public_key) {
      try {
        let normalized;
        // If it's already a Buffer, verify it doesn't contain ASCII-hex/base64 text
        if (Buffer.isBuffer(authenticator.credential_public_key)) {
          const asText = authenticator.credential_public_key.toString('utf8').trim();
          if (/^[0-9a-fA-F]+$/.test(asText) && asText.length % 2 === 0) {
            normalized = Buffer.from(asText, 'hex');
            logger.debug(`Converted ASCII-hex Buffer to binary Buffer (${normalized.length} bytes)`);
          } else {
            // Try base64 heuristic: valid base64 is multiple of 4 and decodes without error
            if (asText.length % 4 === 0 && /^[A-Za-z0-9+/=]+$/.test(asText)) {
              try {
                const b64 = Buffer.from(asText, 'base64');
                if (b64.length > 0) {
                  normalized = b64;
                  logger.debug(`Converted base64 Buffer text to binary Buffer (${normalized.length} bytes)`);
                }
              } catch {}
            }
            normalized = normalized || authenticator.credential_public_key;
          }
        } 
        // If it's a string, support hex and base64
        else if (typeof authenticator.credential_public_key === 'string') {
          const keyStr = authenticator.credential_public_key.trim();
          if (/^[0-9a-fA-F]+$/.test(keyStr) && keyStr.length % 2 === 0) {
            normalized = Buffer.from(keyStr, 'hex');
            logger.debug(`Converted hex string to Buffer (${normalized.length} bytes)`);
          } else {
            try {
              normalized = Buffer.from(keyStr, 'base64');
              logger.debug(`Converted base64 string to Buffer (${normalized.length} bytes)`);
            } catch {
              throw new Error('Public key string must be hex or base64 encoded');
            }
          }
        } 
        // If it's an object with type 'Buffer' (from JSON serialization)
        else if (authenticator.credential_public_key.type === 'Buffer' && 
                 Array.isArray(authenticator.credential_public_key.data)) {
          normalized = Buffer.from(authenticator.credential_public_key.data);
          logger.debug(`Converted Buffer object to Buffer (${normalized.length} bytes)`);
        }
        // If it's a Uint8Array
        else if (authenticator.credential_public_key instanceof Uint8Array) {
          normalized = Buffer.from(authenticator.credential_public_key);
          logger.debug(`Converted Uint8Array to Buffer (${normalized.length} bytes)`);
        }
        // If it's an array of numbers
        else if (Array.isArray(authenticator.credential_public_key)) {
          normalized = Buffer.from(authenticator.credential_public_key);
          logger.debug(`Converted Array to Buffer (${normalized.length} bytes)`);
        }
        else {
          throw new Error('Unsupported public key format');
        }

        // Assign both helper and original field for downstream consumers
        authenticator.credentialPublicKey = normalized;
        authenticator.credential_public_key = normalized;
      } catch (error) {
        console.error('Error normalizing credential_public_key:', error);
        // Do not fail lookup on normalization; leave as-is and let verify path handle it
      }
    }
    
    return authenticator;
  } catch (error) {
    console.error('Error getting authenticator:', error);
    throw new AuthenticatorError('Failed to get authenticator');
  }
}

/**
 * Get an authenticator by credential ID
 * @param {string} credentialId - The credential ID (hex string)
 * @returns {Promise<Object|null>} The authenticator or null if not found
 */
async function getAuthenticatorByCredentialId(credentialId) {
  try {
    const result = await pool.query(
      `SELECT a.*, u.username, u.email 
       FROM authenticators a 
       JOIN users u ON a.user_id = u.id 
       WHERE a.credential_id = $1`,
      [credentialId]
    );
    if (!result.rows[0]) return null;
    
    const authenticator = {
      ...result.rows[0],
      user_id: result.rows[0].user_id.toString() // Ensure ID is a string
    };
       
    // Normalize credential_public_key to a binary Buffer if needed (no CBOR parsing here)
    if (authenticator.credential_public_key) {
      try {
        let publicKeyBuffer;
        if (typeof authenticator.credential_public_key === 'string') {
          const keyStr = authenticator.credential_public_key.trim();
          if (/^[0-9a-fA-F]+$/.test(keyStr) && keyStr.length % 2 === 0) {
            publicKeyBuffer = Buffer.from(keyStr, 'hex');
            logger.debug(`Converted public key string (hex) -> Buffer (${publicKeyBuffer.length} bytes)`);
          } else {
            try {
              publicKeyBuffer = Buffer.from(keyStr, 'base64');
              logger.debug(`Converted public key string (base64) -> Buffer (${publicKeyBuffer.length} bytes)`);
            } catch {
              throw new Error('Unsupported public key string encoding');
            }
          }
        } else if (authenticator.credential_public_key instanceof Buffer) {
          publicKeyBuffer = authenticator.credential_public_key;
          const asText = publicKeyBuffer.toString('utf8').trim();
          if (/^[0-9a-fA-F]+$/.test(asText) && asText.length % 2 === 0) {
            publicKeyBuffer = Buffer.from(asText, 'hex');
            logger.debug(`Detected ASCII-hex Buffer; converted -> binary (${publicKeyBuffer.length} bytes)`);
          }
        } else {
          throw new Error('Public key must be a string or Buffer');
        }
        authenticator.credential_public_key = publicKeyBuffer;
      } catch (error) {
        console.error('Error normalizing credential_public_key:', error);
        // Do not fail lookup on normalization; leave as-is and let verify path handle it
      }
    }
    
    return authenticator;
  } catch (error) {
    console.error('Error getting authenticator by credential ID:', error);
    throw new AuthenticatorError('Failed to get authenticator by credential ID');
  }
}

/**
 * Update the authenticator's counter
 * @param {number} id - Authenticator ID
 * @param {number} counter - New counter value
 * @returns {Promise<Object>} The updated authenticator
 */
async function updateAuthenticatorCounter(id, counter) {
  try {
    const result = await pool.query(
      'UPDATE authenticators SET counter = $1, updated_at = NOW() WHERE id = $2::uuid RETURNING *',
      [counter, id]
    );
    
    if (result.rows.length === 0) {
      throw new AuthenticatorError('Authenticator not found', 'AUTHENTICATOR_NOT_FOUND');
    }
    
    const authenticator = {
      ...result.rows[0],
      user_id: result.rows[0].user_id?.toString() // Ensure ID is a string if it exists
    };
    
    // Convert credential_public_key to Buffer if it's a string
    if (authenticator.credential_public_key) {
      try {
        if (typeof authenticator.credential_public_key === 'string') {
          // First try to parse as hex
          try {
            authenticator.credential_public_key = Buffer.from(authenticator.credential_public_key, 'hex');
            logger.debug('Converted credential public key from hex to Buffer');
            
            // If the resulting buffer is not valid COSE, try base64
            try {
              // cbor is already imported at the top of the file
              cbor.decodeFirstSync(authenticator.credential_public_key);
            } catch (cborError) {
              logger.debug('Public key is not valid COSE, trying base64...');
              try {
                const base64Key = Buffer.from(authenticator.credential_public_key, 'base64');
                if (base64Key.length > 0) {
                  authenticator.credential_public_key = base64Key;
                  logger.debug('Converted credential public key from base64 to Buffer');
                }
              } catch (base64Error) {
                logger.debug('Failed to parse public key as base64, keeping hex format');
              }
            }
          } catch (hexError) {
            console.error('Failed to parse public key as hex, trying base64...');
            try {
              authenticator.credential_public_key = Buffer.from(authenticator.credential_public_key, 'base64');
              logger.debug('Converted credential public key from base64 to Buffer');
            } catch (base64Error) {
              console.error('Failed to parse public key as base64');
              throw new AuthenticatorError('Invalid credential public key format', 'INVALID_PUBLIC_KEY');
            }
          }
        } else if (authenticator.credential_public_key instanceof Buffer) {
          logger.debug('Credential public key is already a Buffer');
        } else {
          console.error('Unexpected credential_public_key type:', 
            typeof authenticator.credential_public_key);
        }
      } catch (error) {
        console.error('Error processing credential_public_key:', error);
        throw new AuthenticatorError('Invalid credential public key format', 'INVALID_PUBLIC_KEY');
      }
    }
    
    return authenticator;
  } catch (error) {
    console.error('Error updating authenticator counter:', error);
    throw new AuthenticatorError('Failed to update authenticator counter');
  }
}

/**
 * Delete an authenticator by user ID
 * @param {string} userId - User ID (UUID)
 * @returns {Promise<boolean>} True if deleted, false if not found
 */
async function deleteAuthenticator(userId) {
  const client = await pool.connect();
  
  try {
    const result = await client.query(
      'DELETE FROM authenticators WHERE user_id = $1::uuid RETURNING id',
      [userId]
    );
    
    const deleted = result.rowCount > 0;

    // Best-effort: remove userCertificate from LDAP if we deleted the authenticator
    if (deleted) {
      try {
        await removeLdapUserCertificate(userId);
      } catch (ldapErr) {
        console.error('Failed to remove LDAP userCertificate for user', userId, ldapErr);
      }
    }

    return deleted;
  } catch (error) {
    console.error('Error deleting authenticator:', error);
    throw new AuthenticatorError('Failed to delete authenticator');
  } finally {
    client.release();
  }
}

/**
 * Update an authenticator's details
 * @param {string} id - Authenticator ID
 * @param {Object} updates - Fields to update
 * @param {string} [updates.name] - New name for the authenticator
 * @param {string[]} [updates.transports] - Updated transports list
 * @returns {Promise<Object>} The updated authenticator
 */
async function updateAuthenticator(id, updates) {
  const client = await pool.connect();
  
  try {
    const updateFields = [];
    const values = [];
    let paramIndex = 1;
    
    // Build the SET clause dynamically based on provided updates
    if (updates.name !== undefined) {
      updateFields.push(`name = $${paramIndex++}`);
      values.push(updates.name);
    }
    
    if (updates.transports !== undefined) {
      updateFields.push(`transports = $${paramIndex++}`);
      values.push(updates.transports);
    }
    
    // Add updated_at timestamp
    updateFields.push(`updated_at = NOW()`);
    
    if (updateFields.length === 0) {
      throw new Error('No fields to update');
    }
    
    // Add the ID to the values array
    values.push(id);
    
    const query = `
      UPDATE authenticators 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramIndex}::uuid
      RETURNING *
    `;
    
    const result = await client.query(query, values);
    
    if (result.rows.length === 0) {
      throw new AuthenticatorError('Authenticator not found', 'AUTHENTICATOR_NOT_FOUND');
    }
    
    const authenticator = {
      ...result.rows[0],
      user_id: result.rows[0].user_id?.toString() // Ensure ID is a string if it exists
    };
    
    // Convert credential_public_key to Buffer if it's a string
    if (authenticator.credential_public_key) {
      try {
        if (typeof authenticator.credential_public_key === 'string') {
          // First try to parse as hex
          try {
            authenticator.credential_public_key = Buffer.from(authenticator.credential_public_key, 'hex');
            console.log('Converted credential public key from hex to Buffer');
            
            // If the resulting buffer is not valid COSE, try base64
            try {
              // cbor is already imported at the top of the file
              cbor.decodeFirstSync(authenticator.credential_public_key);
            } catch (cborError) {
              console.log('Public key is not valid COSE, trying base64...');
              try {
                const base64Key = Buffer.from(authenticator.credential_public_key, 'base64');
                if (base64Key.length > 0) {
                  authenticator.credential_public_key = base64Key;
                  console.log('Converted credential public key from base64 to Buffer');
                }
              } catch (base64Error) {
                console.log('Failed to parse public key as base64, keeping hex format');
              }
            }
          } catch (hexError) {
            console.error('Failed to parse public key as hex, trying base64...');
            try {
              authenticator.credential_public_key = Buffer.from(authenticator.credential_public_key, 'base64');
              console.log('Converted credential public key from base64 to Buffer');
            } catch (base64Error) {
              console.error('Failed to parse public key as base64');
              throw new AuthenticatorError('Invalid credential public key format', 'INVALID_PUBLIC_KEY');
            }
          }
        } else if (authenticator.credential_public_key instanceof Buffer) {
          console.log('Credential public key is already a Buffer');
        } else {
          console.error('Unexpected credential_public_key type:', 
            typeof authenticator.credential_public_key);
        }
      } catch (error) {
        console.error('Error processing credential_public_key:', error);
        throw new AuthenticatorError('Invalid credential public key format', 'INVALID_PUBLIC_KEY');
      }
    }
    
    return authenticator;
  } catch (error) {
    console.error('Error updating authenticator:', error);
    throw new AuthenticatorError(
      error.message || 'Failed to update authenticator',
      error.code
    );
  } finally {
    client.release();
  }
}

/**
 * Rename an authenticator
 * @param {string} userId - User ID (UUID)
 * @param {string} name - New name for the authenticator
 * @returns {Promise<Object>} The updated authenticator
 */
async function renameAuthenticator(userId, name) {
  try {
    const result = await pool.query(
      `UPDATE authenticators 
       SET name = $1,
           updated_at = NOW()
       WHERE user_id = $2::uuid
       RETURNING *`,
      [name, userId]
    );
    
    if (result.rows[0]) {
      result.rows[0].user_id = result.rows[0].user_id.toString(); // Ensure ID is a string
    }
    
    if (result.rows.length === 0) {
      throw new AuthenticatorError('Authenticator not found', 'AUTHENTICATOR_NOT_FOUND');
    }
    
    return result.rows[0];
  } catch (error) {
    console.error('Error renaming authenticator:', error);
    throw new AuthenticatorError('Failed to rename authenticator');
  }
}

export {
  saveAuthenticator,
  getAuthenticatorByUserId,
  getAuthenticatorByCredentialId,
  updateAuthenticatorCounter,
  deleteAuthenticator,
  updateAuthenticator,
  renameAuthenticator,
  coseToSSH,
  upsertLdapUserCertificate,
  removeLdapUserCertificate,
  updateAuthenticatorSSHMetadata,
  AuthenticatorError
};

// ----- LDAP integration helpers -----

async function buildUserDNFromId(userId) {
  const user = await getUserById(userId);
  if (!user || !user.username) {
    throw new Error(`Cannot resolve username for userId=${userId}`);
  }

  try {
    // Search for the user by uid (username)
    const { searchEntries } = await ldapClientInstance.search(
      process.env.LDAP_SEARCH_BASE_USERS || 'dc=example,dc=org',
      {
        scope: 'sub',
        filter: `(uid=${user.username})`,
        attributes: ['dn'],
        paged: false,
        sizeLimit: 1
      }
    );

    if (!searchEntries || searchEntries.length === 0) {
      throw new Error(`User ${user.username} not found in LDAP`);
    }

    // Return the DN from the search result
    return searchEntries[0].dn;
  } catch (error) {
    console.error('[LDAP] Error searching for user DN:', error);
    throw new Error(`Failed to retrieve DN for user ${user.username}: ${error.message}`);
  }
}


/**
 * Convert a COSE key to SSH public key format
 * @param {Buffer|Uint8Array} publicKey - The COSE-encoded public key
 * @param {string} username - The username to include in the key comment
 * @returns {string} The SSH public key in OpenSSH format
 */
function coseToSSH(publicKey, username) {
  try {
    // Parse the COSE key (handle trailing extension maps)
    let coseKey;
    try {
      coseKey = cbor.decodeFirstSync(publicKey);
    } catch (decodeError) {
      if (decodeError?.name === 'UnexpectedDataError' || /Unexpected data/i.test(decodeError?.message || '')) {
        console.log('coseToSSH: decodeFirstSync found trailing data, using decodeAllSync');
        const decodedItems = cbor.decodeAllSync(publicKey);
        if (decodedItems.length === 0) {
          throw new Error('COSE key buffer decoded to no items');
        }
        // Reuse the first decoded item
        coseKey = decodedItems[0];
        if (decodedItems.length > 1) {
          console.log('coseToSSH: ignoring trailing COSE items:', decodedItems.length - 1);
        }
      } else {
        throw decodeError;
      }
    }

    // Build comment domain from LDAP first, then fallback to RP ID
    const domainFromBase = (() => {
      const base = process.env.LDAP_SEARCH_BASE_USERS || process.env.LDAP_SEARCH_BASE || 'dc=example,dc=org';
      const parts = base.match(/dc=([^,]+)/gi);
      if (parts && parts.length) {
        return parts.map(p => p.split('=')[1]).join('.');
      }
      return null;
    })();
    const commentDomain = process.env.LDAP_DOMAIN || domainFromBase || process.env.FIDO2_RP_ID || 'example.org';
    const comment = `${username}@${commentDomain}`;
    
    // Prefer SK OpenSSH formats for WebAuthn so public keys match stubs and LDAP
    try {
      const kt = detectKeyTypeFromCOSE(publicKey);
      if (kt === 'sk-ecdsa-sha2-nistp256@openssh.com' || kt === 'sk-ssh-ed25519@openssh.com') {
        return coseToOpenSSHFidoPub(publicKey, kt, comment, process.env.FIDO2_RP_ID);
      }
    } catch {}

    // Fallback legacy handling (non-SK keys)
    const kty = coseKey.get(1);
    if (kty === 1) {
      const curve = coseKey.get(-1);
      let x = coseKey.get(-2);
      if (!x) throw new Error('Missing x coordinate/public key for OKP');
      if (!Buffer.isBuffer(x)) x = Buffer.from(x);
      if (curve !== 6) throw new Error(`Unsupported OKP curve: ${curve}`);
      const keyType = Buffer.from('ssh-ed25519');
      const sshKeyBlob = Buffer.concat([
        Buffer.from([0x00, 0x00, 0x00, keyType.length]),
        keyType,
        Buffer.from([0x00, 0x00, 0x00, x.length]),
        x
      ]);
      return `ssh-ed25519 ${sshKeyBlob.toString('base64')} ${comment}`;
    }
    if (kty === 2) {
      const curve = coseKey.get(-1);
      let x = coseKey.get(-2);
      let y = coseKey.get(-3);
      if (!Buffer.isBuffer(x)) x = Buffer.from(x);
      if (!Buffer.isBuffer(y)) y = Buffer.from(y);
      let curveName;
      if (curve === 1) curveName = 'nistp256';
      else if (curve === 2) curveName = 'nistp384';
      else if (curve === 3) curveName = 'nistp521';
      else throw new Error(`Unsupported curve: ${curve}`);
      const keyType = Buffer.from('ecdsa-sha2-' + curveName);
      const curveNameBuf = Buffer.from(curveName);
      const publicKeyPoint = Buffer.allocUnsafe(1 + x.length + y.length);
      publicKeyPoint[0] = 0x04;
      x.copy(publicKeyPoint, 1);
      y.copy(publicKeyPoint, 1 + x.length);
      const sshKeyBlob = Buffer.concat([
        Buffer.from([0x00, 0x00, 0x00, keyType.length]),
        keyType,
        Buffer.from([0x00, 0x00, 0x00, curveNameBuf.length]),
        curveNameBuf,
        Buffer.from([0x00, 0x00, 0x00, publicKeyPoint.length]),
        publicKeyPoint
      ]);
      return `ecdsa-sha2-${curveName} ${sshKeyBlob.toString('base64')} ${comment}`;
    }
    if (kty === 3) {
      let n = coseKey.get(-1);
      let e = coseKey.get(-2);
      if (!Buffer.isBuffer(n)) n = Buffer.from(n);
      let eBuf = Buffer.isBuffer(e) ? e : Buffer.from(e);
      if (eBuf.length === 1 && eBuf[0] === 0x11) {
        eBuf = Buffer.from([0x01, 0x00, 0x01]);
      }
      const keyType = Buffer.from('ssh-rsa');
      const sshKeyBlob = Buffer.concat([
        Buffer.from([0x00, 0x00, 0x00, keyType.length]),
        keyType,
        Buffer.from([0x00, 0x00, 0x00, eBuf.length]),
        eBuf,
        Buffer.from([0x00, 0x00, 0x00, n.length]),
        n
      ]);
      return `ssh-rsa ${sshKeyBlob.toString('base64')} ${comment}`;
    }
    throw new Error(`Unsupported key type: ${kty}`);
  } catch (err) {
    console.error('Error converting COSE to SSH format:', err);
    throw new Error('Failed to convert public key to SSH format');
  }
}

/**
 * Upsert a user's SSH public key in LDAP
 * @param {string} userId - The user's ID
 * @param {Buffer|Uint8Array} publicKey - The COSE-encoded public key
 * @param {string} [username] - Optional username for the key comment
 * @returns {Promise<Object>} Result of the operation
 */
async function upsertLdapUserCertificate(userId, publicKey, username) {
  if (!publicKey) {
    throw new Error('Public key is required');
  }
  
  try {
    // Bind to LDAP and get the user's DN
    await ldapClientInstance.bind(
      process.env.LDAP_ADMIN_DN,
      process.env.LDAP_ADMIN_PASSWORD
    );
    const dn = await buildUserDNFromId(userId);
    
    // Check if the public key is already in PEM format
    let sshPublicKey;
    if (typeof publicKey === 'string' && publicKey.includes('-----BEGIN PUBLIC KEY-----')) {
      // Key is already in PEM format, just use it directly
      sshPublicKey = publicKey;
    } else {
      // Convert COSE key to SSH format with username in comment
      sshPublicKey = coseToSSH(publicKey, username);
    }
    
    console.log('[LDAP] Storing WebAuthn public key in SSH format:');
    console.log(`- User DN: ${dn}`);
    console.log(`- Key type: ${sshPublicKey.split(' ')[0]}`);
    
    try {
      // 1. First ensure the objectClass exists
      try {
        await ldapClientInstance.modify(dn, [
          new Change({
            operation: 'add',
            modification: new Attribute({
              type: 'objectClass',
              values: ['ldapPublicKey']
            })
          })
        ]);
      } catch (err) {
        if (err.code !== 20) { // Ignore if objectClass already exists
          throw err;
        }
      }
      
      // 2. Update the SSH public key
      try {
        await ldapClientInstance.modify(dn, [
          // Add the new SSH public key
          new Change({
            operation: 'add',
            modification: new Attribute({
              type: 'sshPublicKey',
              values: [sshPublicKey]
            })
          })
        ]);
      } catch (error) {
        // If add fails, try replace instead
        if (error.code === 20 || error.code === 21) { // Type or value exists or invalid syntax
          await ldapClientInstance.modify(dn, [
            new Change({
              operation: 'replace',
              modification: new Attribute({
                type: 'sshPublicKey',
                values: [sshPublicKey]
              })
            })
          ]);
        } else {
          throw error;
        }
      }
      
      console.log(`[LDAP] Successfully upserted SSH public key for ${dn}`);
      return { success: true };
      
    } catch (err) {
      // Handle specific LDAP error codes
      if (err.code === 16) { // No such attribute
        console.warn('[LDAP] SSH public key attribute does not exist (this may be expected)');
        
        // Try to add the objectClass and attribute
        try {
          console.log('[LDAP] Attempting to add ldapPublicKey objectClass to user entry');
          await ldapClientInstance.client.modify(dn, [
            new Change({
              operation: 'add',
              modification: new Attribute({
                type: 'objectClass',
                values: ['ldapPublicKey']
              })
            })
          ]);
          
          // Now try to add the SSH public key again
          console.log('[LDAP] Retrying SSH public key addition');
          await ldapClientInstance.modify(dn, [
            new Change({
              operation: 'add',
              modification: new Attribute({
                type: 'sshPublicKey',
                values: [sshPublicKey]
              })
            })
          ]);
          
          console.log(`[LDAP] Successfully added SSH public key after schema update for ${dn}`);
          return { success: true };
          
        } catch (retryErr) {
          console.error('[LDAP] Failed to update schema or add SSH key:', retryErr);
          throw new Error(`Failed to store SSH public key: ${retryErr.message}`);
        }
        
      } else if (err.code === 20) { // Type or value already exists
        console.warn('[LDAP] Object class already exists (this is expected)');
      } else if (err.code === 21) { // Invalid attribute syntax
        console.error('[LDAP] Invalid attribute syntax for sshPublicKey. Schema may be incorrect.');
        throw new Error('Invalid SSH public key format. Please check LDAP schema.');
      } else {
        console.error('[LDAP] Error in LDAP modify operation:', {
          code: err.code,
          message: err.message,
          name: err.name,
          stack: err.stack
        });
        throw err;
      }
    }
  } catch (err) {
    console.error('[LDAP] Error updating userCertificate:', err);
    throw err;
  } finally {
    try { await ldapClientInstance.unbind(); } catch {}
  }
}

async function removeLdapUserCertificate(userId) {
  if (!userId) {
    throw new Error('User ID is required');
  }
  
  try {
    await ldapClientInstance.bind(
      process.env.LDAP_ADMIN_DN,
      process.env.LDAP_ADMIN_PASSWORD
    );
    const dn = await buildUserDNFromId(userId);
    
    console.log(`[LDAP] Removing SSH public key for user DN: ${dn}`);
    
    try {
      // First, try to get the current entry to check attributes
      const { searchEntries } = await ldapClientInstance.search(dn, {
        scope: 'base',
        attributes: ['objectClass', 'sshPublicKey']
      });
      
      if (!searchEntries || searchEntries.length === 0) {
        console.log('[LDAP] User entry not found:', dn);
        return { success: false, error: 'User entry not found', removed: false };
      }
      
      const entry = searchEntries[0];
      const changes = [];
      let hasChanges = false;
      
      // 1. Remove SSH public key if it exists
      if (entry.sshPublicKey) {
        changes.push(
          new Change({
            operation: 'delete',
            modification: new Attribute({
              type: 'sshPublicKey',
              values: []
            })
          })
        );
        hasChanges = true;
      }
      
      // No need to handle fingerprints anymore
      
      // Only execute modify if there are changes to make
      if (hasChanges) {
        await ldapClientInstance.modify(dn, changes);
        console.log(`[LDAP] Successfully removed SSH public key for ${dn}`);
        
        // Check if we should remove the ldapPublicKey objectClass
        const objectClasses = entry.objectClass || [];
        if (objectClasses.includes('ldapPublicKey')) {
          try {
            await ldapClientInstance.modify(dn, [
              new Change({
                operation: 'delete',
                modification: new Attribute({
                  type: 'objectClass',
                  values: ['ldapPublicKey']
                })
              })
            ]);
            console.log('[LDAP] Removed ldapPublicKey objectClass');
          } catch (e) {
            console.warn('[LDAP] Could not remove ldapPublicKey objectClass (may be required by other attributes):', e.message);
          }
        }
        
        return { success: true, removed: true };
      } else {
        console.log('[LDAP] No SSH public key attributes to remove');
        return { success: true, removed: false };
      }
      
    } catch (err) {
      // Handle specific LDAP errors
      if (err.name === 'NoSuchObjectError' || err.code === 32) {
        console.log('[LDAP] User entry not found:', dn);
        return { success: false, error: 'User entry not found', removed: false };
      } else if (err.code === 16) { // No such attribute
        console.log('[LDAP] SSH public key attributes not present');
        return { success: true, removed: false };
      }
      console.error('[LDAP] Error removing SSH public key:', err);
      throw err; // Re-throw other errors
    }
  } catch (err) {
    console.error('[LDAP] Error in removeLdapUserCertificate:', err);
    return { 
      success: false, 
      error: err.message || 'Failed to remove SSH public key',
      removed: false 
    };
  } finally {
    try { await ldapClientInstance.unbind(); } catch {}
  }
}
