import base64url from 'base64url';
import crypto from 'crypto';
import cbor from 'cbor';
import { 
  getAuthenticatorByUserId, 
  saveAuthenticator, 
  updateAuthenticatorCounter, 
  deleteAuthenticator
} from '../db/authenticatorOps.js';
import { detectKeyTypeFromCOSE, coseToOpenSSHFidoPub } from './sshKeys.js';
import { addSSHPublicKeyToLDAP } from '../services/ldapSSHKeyService.js';
import { getDeviceName } from './authenticatorMetadata.js';
import { getUserById } from '../db/userOps.js';
import { 
  verifyRegistrationResponse, 
  verifyAuthenticationResponse 
} from '@simplewebauthn/server';
import pool from '../db/index.js';
import { isDebugEnabled, logger } from './logger.js';

/**
 * Normalize a display name according to RFC 8264 (PRECIS OpaqueString profile)
 * @param {string} displayName - The display name to normalize
 * @returns {string} The normalized display name
 */
function normalizeDisplayName(displayName) {
  let normalized = '';
  if (typeof displayName !== 'string') {
    normalized = '';
  } else {
    // 1. Apply Unicode Normalization Form C (NFC)
    normalized = displayName.normalize('NFC');
    // 2. Trim leading and trailing whitespace
    normalized = normalized.trim();
    // 3. Replace any sequence of one or more whitespace characters with a single space (U+0020)
    normalized = normalized.replace(/\s+/g, ' ');
    // 4. Ensure the string is not empty after normalization
    if (normalized.length === 0) {
      normalized = '';
    }
    // 5. Ensure the string is not too long (1024 characters is a reasonable limit)
    if (normalized.length > 1024) {
      normalized = normalized.substring(0, 1024);
    }
  }

  return normalized;
}

// Get RP ID from environment or use 'localhost' as fallback
const rpID = process.env.FIDO2_RP_ID;

const VALID_USER_VERIFICATION_VALUES = new Set(['required', 'preferred', 'discouraged']);
//TODO: Clean this up 
const DEFAULT_USER_VERIFICATION = (() => {
  const raw = process.env.FIDO2_USER_VERIFICATION?.toLowerCase();
  if (raw && VALID_USER_VERIFICATION_VALUES.has(raw)) {
    return raw;
  }
  return 'preferred';
})();

// UUID v4 validation regex (case-insensitive)
const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// COSE algorithm identifiers to names mapping
const COSE_ALGORITHMS = {
  '-7': 'ES256',
  '-8': 'EdDSA',
  '-35': 'ES384',
  '-36': 'ES512',
  '-257': 'RS256',
  '-65535': 'RS1'
};

// COSE curve identifiers to names mapping
const COSE_CURVES = {
  '1': 'P-256',
  '2': 'P-384',
  '3': 'P-521',
  '4': 'X25519',
  '5': 'X448',
  '6': 'Ed25519',
  '7': 'Ed448'
};

class WebAuthnError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'WebAuthnError';
    this.code = code;
  }
}

/**
 * Get algorithm name from COSE algorithm identifier
 * @param {number} alg - COSE algorithm identifier
 * @returns {string} Algorithm name
 */
function getAlgorithmName(alg) {
  return COSE_ALGORITHMS[alg.toString()] ?? `Unknown (${alg})`;
}

/**
 * Get curve name from COSE curve identifier
 * @param {number} crv - COSE curve identifier
 * @returns {string} Curve name
 */
function getCurveName(crv) {
  return COSE_CURVES[crv.toString()] ?? `Unknown (${crv})`;
}

function firstNonEmptyString(...values) {
  for (const v of values) {
    if (typeof v === 'string' && v.trim().length) return v;
  }
  return undefined;
}

/**
 * Generate registration options for a user
 * @param {string} userId - User ID (UUID string)
 * @param {string} username - Username
 * @param {string} userDisplayName - User's display name
 * @returns {Promise<Object>} Registration options
 */
async function generateWebAuthnRegistrationOptions(userId, username, userDisplayName) {
  try {
    logger.debug('Generating WebAuthn registration options for user:', { userId, username });
    
    // Validate user ID
    if (!userId) {
      throw new WebAuthnError('User ID is required', 'INVALID_USER_ID');
    }
    
    // Ensure userId is a string
    const userIdStr = String(userId).trim();
    
    // Validate UUID format
    if (!uuidRegex.test(userIdStr)) {
      throw new WebAuthnError('Invalid user ID format', 'INVALID_USER_ID_FORMAT');
    }

    // Check if user already has an authenticator
    const existingAuth = await getAuthenticatorByUserId(userIdStr);
    
    // If user already has an authenticator, throw an error
    if (existingAuth) {
      throw new WebAuthnError('User already has an authenticator registered', 'AUTHENTICATOR_EXISTS');
    }

    // Ensure RP_ID is set
    if (!rpID) {
      throw new WebAuthnError('Relying Party ID (RP_ID) is not configured', 'CONFIGURATION_ERROR');
    }
    
    // Convert user ID to Buffer for WebAuthn
    const userIdBuffer = Buffer.from(userIdStr.replace(/-/g, ''), 'hex');
    
    logger.debug('Creating registration options with:', {
      rpID,
      displayName: userDisplayName,
      username,
      userIdLength: userIdBuffer.length
    });
    
    try {
      // Generate a random challenge
      const challenge = crypto.randomBytes(32);
      
      // Generate user information with RFC 8264 compliant display name
      const displayName = firstNonEmptyString(
        userDisplayName,
        username,
        `User-${userId.substring(0, 8)}`
      );
      const userDisplayNameNormalized = normalizeDisplayName(displayName);
      
      if (!userDisplayNameNormalized) {
        throw new WebAuthnError('Invalid display name after normalization', 'INVALID_DISPLAY_NAME');
      }
      
      logger.debug('Generating registration options with display name (normalized):', userDisplayNameNormalized);
  
      const options = {
        rp: {
          name: process.env.FIDO2_RP_NAME,
          id: rpID
        },
        user: {
          id: userIdBuffer,
          name: String(username),
          displayName: userDisplayNameNormalized,
        },
        challenge: challenge,
        pubKeyCredParams: [ // Position in array marks priority
          { type: 'public-key', alg: -8 }, // "EdDSA" (Ed25519 via crv=6) [Recommended]
          { type: 'public-key', alg: -36 }, // "ES512" (ECDSA w/ SHA-512) [Optional]
          { type: 'public-key', alg: -35 }, // "ES384" (ECDSA w/ SHA-384) [Recommended]
          { type: 'public-key', alg: -7 }, // "ES256" (ECDSA w/ SHA-256) [Required]
          { type: 'public-key', alg: -257 }, // "RS256" (RSASSA-PKCS1-v1_5 using SHA-256) [Required]
          { type: 'public-key', alg: -65535 } // "RS1" (RSASSA-PKCS1-v1_5 using SHA-1) [Required by FIDO Server Requirements and Transport Binding Profile]
        ],
        timeout: 60000,
        excludeCredentials: [],
        authenticatorSelection: {
          // Hardware-only: external (roaming) authenticators
          authenticatorAttachment: 'cross-platform',
          // Require resident keys (discoverable credentials) for SSH/resident workflows
          requireResidentKey: true,
          residentKey: 'required',
          // Keep UV strong but configurable via env default
          userVerification: DEFAULT_USER_VERIFICATION
        },
        // Request attestation so AAGUID/manufacturer data is available
        attestation: 'indirect',
        extensions: {
          credProps: true
        }
      };
      
      // Store the challenge in the database
      await storeChallenge(userIdStr, base64url.encode(challenge), 'registration');

      // Log RP ID and challenge prefix for diagnostics
      logger.debug('[WebAuthn] Registration options', {
        rpID,
        challengePrefix: challenge.toString('base64url').substring(0, 12)
      });
      
      logger.debug('Successfully generated WebAuthn options');
      
      // Return the options directly without using generateRegistrationOptions
      return options;
      
    } catch (error) {
      logger.error('Error in WebAuthn options generation:', {
        error: error.message,
        stack: error.stack,
        rpID,
        userId: userIdStr,
        username,
        userDisplayName
      });
      throw new WebAuthnError('Failed to generate registration options: ' + error.message, 'REGISTRATION_OPTIONS_ERROR');
    }
  } catch (error) {
    logger.error('Error in generateWebAuthnRegistrationOptions:', {
      error: error.message,
      stack: error.stack,
      userId: userId ? 'present' : 'missing',
      username: firstNonEmptyString(username, 'missing'),
      rpID: firstNonEmptyString(rpID, 'missing')
    });
    if (error instanceof WebAuthnError) throw error;
    throw new WebAuthnError('Failed to generate registration options: ' + error.message, 'REGISTRATION_ERROR');
  }
}

/**
 * Verify registration response
 * @param {Object} options - Verification options
 * @param {Object} options.credential - Registration response from client
 * @param {string} options.expectedOrigin - Expected origin
 * @param {string} options.expectedRPID - Expected Relying Party ID
 * @param {boolean} options.requireUserVerification - Whether user verification is required
 * @param {string} [options.name] - Optional name for the authenticator
 * @param {string} userId - User ID (UUID string)
 * @returns {Promise<Object>} Verification result
 */
async function verifyRegistration({
  credential,
  expectedOrigin,
  expectedRPID,
  requireUserVerification = true,
  name = 'Security Key', // Default name if not provided
  userDisplayName = null // User's display name for the authenticator
}, userId) {
  try {
    if (!userId || typeof userId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId)) {
      throw new WebAuthnError('Invalid user ID format', 'INVALID_USER_ID');
    }

    logger.debug('Starting registration verification for user:', userId);
    
    // Get the stored challenge using the local getChallenge function
    const expectedChallenge = await getChallenge(userId, 'registration');
    if (!expectedChallenge) {
      logger.error('No registration challenge found for user:', userId);
      throw new WebAuthnError('No registration challenge found', 'CHALLENGE_NOT_FOUND');
    }
    
    logger.debug('Retrieved expected challenge for user:', userId);
    
    // Verify the registration response
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: expectedChallenge,
        expectedOrigin: expectedOrigin,
        expectedRPID: expectedRPID,
        requireUserVerification: requireUserVerification,
        supportedAlgorithmIDs: [-8, -36, -35, -7, -257, -65535],
        debug: isDebugEnabled()
      });
    } catch (e) {
      // Map missing UV error to a stable code we can surface to the client
      const msg = e?.message ?? '';
      if (requireUserVerification && /user verification was required|could not be verified/i.test(msg)) {
        throw new WebAuthnError('User verification is required. Please use your PIN or biometrics on the security key and try again.', 'UV_REQUIRED');
      }
      throw e;
    }
    
    const { verified, registrationInfo } = verification;
    
    logger.debug('Verification result:', {
      verified,
      registrationInfo: registrationInfo ? {
        credentialID: registrationInfo.credentialID ? 'present' : 'missing',
        credentialPublicKey: registrationInfo.credentialPublicKey ? 'present' : 'missing',
        counter: registrationInfo.counter
      } : 'none'
    });
    
    if (verified) {
      logger.debug('Registration verified, processing registration info...');
      
      // Log detailed authenticator information
      try {
        const attestationBuffer = Buffer.from(credential.response.attestationObject, 'base64');
        const attestation = await cbor.decodeFirst(attestationBuffer);
        const authData = parseAuthenticatorData(attestation.authData);
        
        // Get AAGUID if available (for FIDO2 authenticators)
        let aaguid = null;
        if (authData.attestedCredentialData?.aaguid) {
          aaguid = Buffer.from(authData.attestedCredentialData.aaguid).toString('hex');
        } else if (registrationInfo?.aaguid) {
          // Fallback to aaguid exposed by simplewebauthn when available
          const maybeBuf = registrationInfo.aaguid;
          aaguid = Buffer.isBuffer(maybeBuf)
            ? maybeBuf.toString('hex')
            : (typeof maybeBuf === 'string'
                ? maybeBuf.replace(/-/g, '').toLowerCase()
                : null);
        }

        if (aaguid) {
          // Check for zero AAGUID
          if (aaguid === '00000000000000000000000000000000') {
            logger.debug('Zero AAGUID detected, using user display name for authenticator name');
            // Get user's display name from the database using the already imported function
            const user = await getUserById(userId);
            if (user?.displayName) {
              name = `${user.displayName}'s Security Key`;
              logger.debug(`Setting authenticator name to: ${name}`);
            }
          } else {
            // Try to get device name from known AAGUIDs
            const deviceName = getDeviceName(aaguid);
            if (deviceName) {
              name = deviceName;
              logger.debug(`Detected authenticator: ${deviceName} (AAGUID: ${aaguid})`);
            } else {
              logger.debug(`Unknown authenticator AAGUID: ${aaguid}`);
            }
          }
        }
        
        // Get authenticator metadata if available
        const authenticatorMetadata = {
          aaguid: firstNonEmptyString(aaguid, 'Not provided'),
          credentialId: authData.attestedCredentialData?.credentialID?.length ? 
                       `[${authData.attestedCredentialData.credentialID.length} bytes]` : 
                       'Not available',
          publicKey: authData.attestedCredentialData?.credentialPublicKey ? 
                    `[${authData.attestedCredentialData.credentialPublicKey.length} bytes]` : 
                    'Not available',
          counter: authData.counter,
          userVerified: !!(authData.flags & 0x04),
          userPresent: !!(authData.flags & 0x01),
          attestedCredentialData: !!authData.attestedCredentialData,
          extensionData: authData.extensionData ?? 'None',
          fmt: attestation.fmt,
          attestationStatement: attestation.attStmt ? Object.keys(attestation.attStmt) : 'None',
          transports: credential.transports ?? 'Not specified',
          clientExtensionResults: credential.clientExtensionResults ?? {},
          authenticatorName: name // Include the determined authenticator name
        };
        
        logger.debug('Authenticator Metadata:', JSON.stringify(authenticatorMetadata, null, 2));
      } catch (error) {
        logger.error('Error logging authenticator metadata:', error);
      }
      
      // Try to get credential ID from different possible locations
      let credentialID = registrationInfo?.credentialID ?? credential.rawId ?? credential.id;
      
      // If we still don't have a credential ID, try to extract it from the response
      if (!credentialID && credential.response) {
        try {
          const clientData = JSON.parse(
            Buffer.from(credential.response.clientDataJSON, 'base64').toString()
          );
          logger.debug('Client data from response:', clientData);
          
          // Try to get credential ID from the response if available
          if (credential.response.getPublicKey) {
            const publicKey = credential.response.getPublicKey();
            if (publicKey) {
              credentialID = crypto.createHash('sha256').update(publicKey).digest();
              logger.debug('Generated credential ID from public key');
            }
          }
        } catch (e) {
          logger.error('Error extracting credential ID from response:', e);
        }
      }

      if (!credentialID) {
        logger.error('No credential ID could be determined from registration');
        throw new WebAuthnError('Could not determine credential ID from registration', 'INVALID_REGISTRATION');
      }

      // Convert credentialID to Buffer if it's not already
      const credentialIDBuffer = Buffer.isBuffer(credentialID)
        ? credentialID
        : credentialID instanceof Uint8Array
          ? Buffer.from(credentialID)
          : Buffer.from(credentialID, 'base64url');
      
      // Get public key from registration info or try to extract it
      let publicKey = null;
      let authData = null;
      let attestation = null;
      let userVerified = false;
      
      // Debug: Log the registration info if available
      if (registrationInfo) {
        logger.debug('Registration info:', {
          credentialID: registrationInfo.credentialID ? `[${registrationInfo.credentialID.length} bytes]` : 'none',
          credentialPublicKey: registrationInfo.credentialPublicKey ? 
            `[${registrationInfo.credentialPublicKey.length} bytes]` : 'none',
          counter: registrationInfo.counter,
          fmt: registrationInfo.fmt,
          aaguid: registrationInfo.aaguid
        });
        
        if (registrationInfo.credentialPublicKey) {
          logger.debug('Registration info public key type:', typeof registrationInfo.credentialPublicKey);
          if (Buffer.isBuffer(registrationInfo.credentialPublicKey)) {
            logger.debug('Registration info public key is a Buffer');
          } else if (typeof registrationInfo.credentialPublicKey === 'object') {
            logger.debug('Registration info public key is an object, converting to Buffer');
            // Convert Uint8Array to Buffer if needed
            if (registrationInfo.credentialPublicKey instanceof Uint8Array) {
              registrationInfo.credentialPublicKey = Buffer.from(registrationInfo.credentialPublicKey);
            }
          }
        }
      }
      
      if (credential.response?.attestationObject) {
        try {
          const attestationBuffer = Buffer.from(credential.response.attestationObject, 'base64');
          logger.debug('Attestation object size:', attestationBuffer.length);
          
          // Parse the CBOR-encoded attestation object
          attestation = await cbor.decodeFirst(attestationBuffer);
          logger.debug('Attestation format:', attestation?.fmt ?? 'none');
          
          // The authData is in the 'authData' field of the attestation statement
          if (attestation?.authData) {
            // Parse the authenticator data
            authData = parseAuthenticatorData(attestation.authData);
            
            // The public key is in the attestedCredentialData field
            if (authData.attestedCredentialData) {
              publicKey = authData.attestedCredentialData.credentialPublicKey;
              // Set userVerified from authenticator data UV flag (not UP)
              userVerified = !!(authData.flags?.uv);
              logger.debug('Extracted public key from attestation', { userVerified });
              
              // If we have a credential ID in the auth data, use it
              if (authData.attestedCredentialData.credentialId && !credentialID) {
                credentialID = authData.attestedCredentialData.credentialId;
                logger.debug('Using credential ID from auth data');
              }
            }
          }
        } catch (e) {
          logger.error('Error parsing attestation object:', e);
          // Fall back to using the raw auth data if available
          if (credential.response.getAuthenticatorData) {
            try {
              authData = credential.response.getAuthenticatorData();
              if (authData) {
                publicKey = authData.get('credentialPublicKey');
                if (publicKey) {
                  logger.debug('Extracted public key from authenticator data');
                }
              }
            } catch (innerError) {
              logger.error('Error getting authenticator data:', innerError);
            }
          }
        }
      }

      if (!publicKey) {
        throw new WebAuthnError('Could not extract public key from registration', 'INVALID_PUBLIC_KEY');
      }

      // Get transports if available
      const transports = credential.transports ??
                        (credential.response && credential.response.getTransports ? 
                          credential.response.getTransports() : ['internal']);

      // Get user information
      const user = await getUserById(userId);
      if (!user) {
        throw new WebAuthnError('User not found', 'USER_NOT_FOUND');
      }
      
      // Ensure we have a properly normalized display name according to RFC 8264
      const displayName = normalizeDisplayName(
        firstNonEmptyString(
          userDisplayName,
          user.displayName,
          user.username,
          `User-${userId.substring(0, 8)}`
        )
      );
      
      if (!displayName) {
        throw new WebAuthnError('Invalid display name after normalization', 'INVALID_DISPLAY_NAME');
      }
      
      logger.debug('Using normalized display name for authenticator:', displayName);
      
      // Ensure we have authData with defaults if not already set
      if (!authData) {
        authData = { 
          signCount: 0, 
          attestedCredentialData: {},
          flags: { up: true, uv: true } // Set user presence and verification flags
        };
      }
      
      // Enforce hardware-only policy based on SimpleWebAuthn metadata when available
      const deviceType = registrationInfo?.credentialDeviceType ?? 'singleDevice';
      const backedUp = !!registrationInfo?.credentialBackedUp;
      if (deviceType === 'multiDevice' || backedUp) {
        throw new WebAuthnError('Roaming/synced passkeys are not allowed. Please register a hardware security key.', 'MULTIDEVICE_NOT_ALLOWED');
      }

      // Save the authenticator with the provided name and display name
      const authenticator = await saveAuthenticator({
        userId,
        credentialID: credentialIDBuffer,
        credentialPublicKey: publicKey,
        name: firstNonEmptyString(
          name,
          `${firstNonEmptyString(user.displayName, user.username, 'User')}'s Security Key`
        ),
        transports: transports ?? ['usb','nfc','ble'],
        userDisplayName: displayName
      });
      
      logger.debug('Authenticator saved with display name:', displayName);

      // Store the SSH public key in LDAP (OpenSSH format) and update DB metadata.
      // Roll back authenticator enrollment on any failure.
      try {
        if (!publicKey || publicKey.length === 0) {
          throw new Error('Missing public key for LDAP upload');
        }

        const publicKeyBuffer = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey);
        // Detect supported key type from COSE
        const sshKeyType = detectKeyTypeFromCOSE(publicKeyBuffer);

        // Build comment as username@domain
        const domainFromBase = (() => {
          const base = process.env.LDAP_SEARCH_BASE_USERS ?? process.env.LDAP_SEARCH_BASE ?? 'dc=example,dc=org';
          const parts = base.match(/dc=([^,]+)/gi);
          if (parts && parts.length) return parts.map(p => p.split('=')[1]).join('.');
          return process.env.FIDO2_RP_ID ?? 'example.org';
        })();
        const comment = `${user.username}@${process.env.LDAP_DOMAIN ?? domainFromBase}`;

        // Convert COSE -> OpenSSH FIDO public key line
        const opensshPub = coseToOpenSSHFidoPub(publicKeyBuffer, sshKeyType, comment, process.env.FIDO2_RP_ID);

        // Upload to LDAP
        await addSSHPublicKeyToLDAP({ username: user.username, opensshPublicKey: opensshPub });

        // Persist SSH metadata to DB
        await pool.query(
          'UPDATE authenticators SET ssh_key_type = $1, ssh_uploaded_at = NOW(), ssh_comment = $2 WHERE id = $3::uuid',
          [sshKeyType, comment, authenticator.id]
        );
      } catch (e) {
        logger.error('Registration rollback due to SSH key handling failure:', e);
        try {
          // Remove the authenticator we just inserted/updated
          await deleteAuthenticator(userId);
        } catch (delErr) {
          logger.error('Failed to roll back authenticator after SSH failure:', delErr);
        }
        throw new WebAuthnError('Failed to finalize SSH key setup. Please try again.', 'SSH_SETUP_FAILED');
      }

      // Return the verification result
      const result = {
        verified: true,
        credentialID: credentialID,
        publicKey: publicKey,
        counter: authData.signCount ?? 0,
        transports: transports ?? ['usb','nfc','ble'],
        aaguid: authData.attestedCredentialData?.aaguid,
        fmt: attestation?.fmt,
        credentialDeviceType: deviceType,
        credentialBackedUp: backedUp,
        name: firstNonEmptyString(name, 'Security Key'),
        userId: userId,
        userHandle: userId,
        userDisplayName: displayName,
        userVerified: userVerified,
        authenticator: {
          id: authenticator.id,
          name: authenticator.name,
          credential_id: authenticator.credential_id,
          created_at: authenticator.created_at
        }
      };
      
      // If caller requires UV and the authenticator did not report UV, treat as failure
      if (requireUserVerification && !result.userVerified) {
        logger.error('Registration failed: user verification (UV) was required but not present.');
        throw new WebAuthnError('User verification required but not performed', 'UV_REQUIRED');
      }
      
      logger.debug('Registration verification successful, returning result:', {
        ...result,
        publicKey: '[REDACTED]',
        credentialID: '[REDACTED]'
      });
      
      return result;
    }
    
    return {
      verified: false,
      error: verification.error ?? 'Verification failed',
      code: 'VERIFICATION_FAILED'
    };
  } catch (error) {
    console.error('Error in verifyRegistration:', error);
    
    if (error instanceof WebAuthnError) {
      throw error;
    }
    
    throw new WebAuthnError(
      error.message ?? 'Registration verification failed',
      error.code ?? 'VERIFICATION_ERROR',
      error.details
    );
  } finally {
  }

}

/**
 * Generate authentication options
 * @param {Object} options - Options for generating authentication
 * @param {string} options.rpID - Relying Party ID
 * @param {string} [options.userVerification='required'] - User verification requirement
 * @param {number} [options.timeout=60000] - Timeout in milliseconds
 * @param {Buffer} userId - User ID (UUID Buffer)
 * @returns {Promise<Object>} Authentication options
 */
async function generateWebAuthnAuthenticationOptions({ rpID, userVerification = DEFAULT_USER_VERIFICATION, timeout = 60000 }, userId) {
  try {
    if (!userId || !(userId instanceof Buffer)) {
      throw new WebAuthnError('Invalid user ID format', 'INVALID_USER_ID');
    }

    // Get the user's authenticator and user details
    const [authenticator, user] = await Promise.all([
      getAuthenticatorByUserId(userId.toString('hex')),
      getUserById(userId.toString('hex'))
    ]);
    
    if (!authenticator) {
      throw new WebAuthnError('No authenticator found for user', 'NO_AUTHENTICATOR');
    }
    
    if (!user) {
      throw new WebAuthnError('User not found', 'USER_NOT_FOUND');
    }
    
    const options = {
      rpID: rpID ?? process.env.FIDO2_RP_ID ?? 'localhost',
      userVerification,
      timeout,
      allowCredentials: [
        {
          type: 'public-key',
          id: Buffer.from(authenticator.credential_id, 'hex'),
          // Hardware-only transports
          transports: Array.isArray(authenticator.transports)
            ? authenticator.transports.filter(t => ['usb','nfc','ble'].includes(t))
            : ['usb','nfc','ble']
        }
      ],
      userID: userId,
      // Include user information for better UX
      user: {
        id: userId,
        name: user.username,
        displayName: user.displayName
      }
    };
    
    // Generate a random challenge
    const challenge = crypto.randomBytes(32);
    options.challenge = challenge;

    // Store the challenge for later verification
    await storeChallenge(userId.toString('hex'), base64url.encode(challenge), 'authentication');

    logger.debug('[WebAuthn] Authentication options', {
      rpID: options.rpID,
      challengePrefix: challenge.toString('base64url').substring(0, 12)
    });
    
    return options;
  } catch (error) {
    console.error('Error generating authentication options:', error);
    if (error instanceof WebAuthnError) {
      throw error; // Re-throw WebAuthnError as is
    }
    
    throw new WebAuthnError(
      error.message ?? 'Failed to generate authentication options',
      error.code ?? 'AUTH_OPTIONS_ERROR'
    );
  }
}

/**
 * Verify authentication response
 * @param {Object} options - Verification options
 * @param {Object} options.credential - Authentication response from client
 * @param {string} options.expectedOrigin - Expected origin
 * @param {string} options.expectedRPID - Expected Relying Party ID
 * @param {boolean} options.requireUserVerification - Whether user verification is required
 * @param {Buffer} userId - User ID (UUID Buffer)
 * @returns {Promise<Object>} Verification result
 */
async function verifyAuthentication({
  credential,
  expectedOrigin,
  expectedRPID,
  requireUserVerification = true
}, userId) {
  try {
    if (!userId || !(userId instanceof Buffer)) {
      throw new WebAuthnError('Invalid user ID format', 'INVALID_USER_ID');
    }

    // Get the stored challenge
    const expectedChallenge = await getChallenge(userId.toString('hex'), 'authentication');
    if (!expectedChallenge) {
      throw new WebAuthnError('No authentication in progress', 'NO_AUTHENTICATION');
    }

    logger.debug('[WebAuthn] Verifying authentication', {
      expectedChallengePrefix: expectedChallenge.substring(0, 12),
      expectedRPID
    });
    
    // Get the authenticator
    const authenticator = await getAuthenticatorByUserId(userId.toString('hex'));
    if (!authenticator) {
      throw new WebAuthnError('No authenticator found for user', 'NO_AUTHENTICATOR');
    }
    // Reject platform-only authenticators (no external transports recorded)
    const recordedTransports = Array.isArray(authenticator.transports) ? authenticator.transports : [];
    const hasExternal = recordedTransports.some(t => ['usb','nfc','ble'].includes(t));
    const onlyInternal = recordedTransports.length > 0 && recordedTransports.every(t => t === 'internal');
    if (!hasExternal || onlyInternal) {
      throw new WebAuthnError('Platform/synced authenticators are not allowed for this service', 'PLATFORM_NOT_ALLOWED');
    }
    
    // Debug: Log the credential public key type and value
    logger.debug('Credential public key type:', typeof authenticator.credential_public_key);
    logger.debug('Credential public key first 100 chars:', 
      typeof authenticator.credential_public_key === 'string' 
        ? authenticator.credential_public_key.substring(0, 100) + '...' 
        : 'Not a string');
    
    // Convert credential public key from hex string to Buffer if needed
    let credentialPublicKey;
    if (typeof authenticator.credential_public_key === 'string') {
      try {
        credentialPublicKey = Buffer.from(authenticator.credential_public_key, 'hex');
        logger.debug('Converted credential public key to Buffer, length:', credentialPublicKey.length);
      } catch (error) {
        console.error('Error converting credential public key from hex to Buffer:', error);
        throw new WebAuthnError('Invalid credential public key format', 'INVALID_PUBLIC_KEY');
      }
    } else if (Buffer.isBuffer(authenticator.credential_public_key)) {
      credentialPublicKey = authenticator.credential_public_key;
      logger.debug('Credential public key is already a Buffer, length:', credentialPublicKey.length);
    } else {
      console.error('Credential public key is neither a string nor a Buffer:', 
        typeof authenticator.credential_public_key);
      throw new WebAuthnError('Invalid credential public key type', 'INVALID_PUBLIC_KEY_TYPE');
    }
    
    // Verify and normalize the public key
    let normalizedPublicKey;
    try {
      logger.debug('Verifying and normalizing public key...');
      normalizedPublicKey = verifyAndNormalizePublicKey(credentialPublicKey);
      logger.debug('Public key verified and normalized successfully');
    } catch (error) {
      console.error('Error normalizing public key:', error);
      throw new WebAuthnError('Invalid public key format: ' + error.message, 'INVALID_PUBLIC_KEY');
    }

    // Prepare authenticator object for verification
    const authenticatorData = {
      credentialID: Buffer.isBuffer(authenticator.credential_id) 
        ? authenticator.credential_id 
        : Buffer.from(authenticator.credential_id, 'hex'),
      credentialPublicKey: normalizedPublicKey,
      counter: Number.isFinite(parseInt(authenticator.counter, 10)) ? parseInt(authenticator.counter, 10) : 0,
      transports: Array.isArray(authenticator.transports) 
        ? authenticator.transports 
        : ['internal']
    };
    
    // Debug: Log the authenticator data being passed to verifyAuthenticationResponse
    logger.debug('Authenticator data for verification:', {
      credentialID: authenticatorData.credentialID.toString('hex').substring(0, 32) + '...',
      credentialPublicKeyType: credentialPublicKey ? credentialPublicKey.constructor.name : 'null',
      credentialPublicKeyLength: credentialPublicKey ? credentialPublicKey.length : 0,
      counter: authenticatorData.counter,
      transports: authenticatorData.transports
    });
    
    if (credentialPublicKey) {
      logger.debug('Credential public key first 32 bytes:', 
        credentialPublicKey.slice(0, 32).toString('hex'));
    }
    
    // Debug: Log detailed info about the authenticator data before verification
    logger.debug('=== Before verifyAuthenticationResponse ===');
    logger.debug('authenticatorData:', {
      credentialID: authenticatorData.credentialID ? 
        `[Buffer ${authenticatorData.credentialID.length} bytes]` : 'null',
      credentialPublicKey: {
        type: credentialPublicKey ? credentialPublicKey.constructor.name : 'null',
        isBuffer: Buffer.isBuffer(credentialPublicKey),
        length: credentialPublicKey ? credentialPublicKey.length : 0,
        firstBytes: credentialPublicKey ? 
          credentialPublicKey.slice(0, 32).toString('hex') : 'null',
        fullType: Object.prototype.toString.call(credentialPublicKey)
      },
      counter: authenticatorData.counter,
      transports: authenticatorData.transports
    });
    
    // Log the full public key in hex for debugging
    if (credentialPublicKey) {
      logger.debug('Full credentialPublicKey hex:', credentialPublicKey.toString('hex'));
      
      // Ensure the public key is in the correct format
      try {
        // Check if it's a valid COSE key by trying to decode it
        const decoded = isoCBOR.decode(credentialPublicKey);
        logger.debug('Successfully decoded COSE key structure:', JSON.stringify(decoded, null, 2));
        
        // Re-encode to ensure it's in the correct format
        const reEncoded = isoCBOR.encode(decoded);
        if (!Buffer.isBuffer(reEncoded)) {
          logger.debug('Re-encoded key is not a Buffer, converting...');
          credentialPublicKey = Buffer.from(reEncoded);
        } else {
          credentialPublicKey = reEncoded;
        }
        logger.debug('Successfully normalized COSE key');
      } catch (decodeError) {
        console.error('Failed to decode COSE key, attempting to fix...');
        
        // Try to fix common issues with the key format
        try {
          // Check if it's a raw EC key (common issue)
          if (credentialPublicKey.length === 65 && credentialPublicKey[0] === 0x04) {
            logger.debug('Detected uncompressed EC key, converting to COSE format...');
            const coseKey = new Map();
            coseKey.set(1, 2);  // kty: EC2 key type
            coseKey.set(3, -7);  // alg: ES256
            coseKey.set(-1, 1);  // crv: P-256
            coseKey.set(-2, credentialPublicKey.slice(1, 33));  // x-coordinate
            coseKey.set(-3, credentialPublicKey.slice(33));     // y-coordinate
            
            const encodedKey = isoCBOR.encode(coseKey);
            credentialPublicKey = Buffer.from(encodedKey);
            logger.debug('Successfully converted raw EC key to COSE format');
          } else {
            console.error('Unsupported key format, cannot automatically fix');
            console.error('Key starts with:', credentialPublicKey.slice(0, 32).toString('hex'));
            throw new WebAuthnError('Unsupported public key format', 'UNSUPPORTED_PUBLIC_KEY');
          }
        } catch (fixError) {
          console.error('Failed to fix key format:', fixError);
          throw new WebAuthnError('Invalid public key format', 'INVALID_PUBLIC_KEY');
        }
      }
      
      // Update the authenticatorData with the normalized key
      authenticatorData.credentialPublicKey = credentialPublicKey;
    }

    // Debug: Log detailed info about the credential public key
    logger.debug('=== Credential Public Key Analysis ===');
    logger.debug('credentialPublicKey type:', typeof credentialPublicKey);
    logger.debug('Is Buffer:', Buffer.isBuffer(credentialPublicKey));
    if (Buffer.isBuffer(credentialPublicKey)) {
      logger.debug('Buffer length:', credentialPublicKey.length);
      logger.debug('First 32 bytes as hex:', credentialPublicKey.slice(0, 32).toString('hex'));
    }
    
    // Debug: Log detailed info about the authenticator data before verification
    logger.debug('=== Authenticator Data Before Verification ===');
    logger.debug('authenticatorData keys:', Object.keys(authenticatorData));
    
    // Ensure credentialPublicKey is set in authenticatorData
    if (!authenticatorData.credentialPublicKey && credentialPublicKey) {
      logger.debug('Setting credentialPublicKey in authenticatorData');
      authenticatorData.credentialPublicKey = credentialPublicKey;
    } else if (authenticatorData.credentialPublicKey) {
      logger.debug('credentialPublicKey already set in authenticatorData');
      logger.debug('Type in authenticatorData:', typeof authenticatorData.credentialPublicKey);
      if (Buffer.isBuffer(authenticatorData.credentialPublicKey)) {
        logger.debug('Buffer length in authenticatorData:', authenticatorData.credentialPublicKey.length);
      }
    }
    
    // Log the structure of authenticatorData
    logger.debug('=== Authenticator Data Details ===');
    const authData = {
      credentialID: authenticatorData.credentialID ? 
        `[Buffer ${authenticatorData.credentialID.length} bytes]` : 'null',
      credentialPublicKey: {
        type: typeof authenticatorData.credentialPublicKey,
        isBuffer: Buffer.isBuffer(authenticatorData.credentialPublicKey),
        length: authenticatorData.credentialPublicKey ? authenticatorData.credentialPublicKey.length : 0,
        firstBytes: authenticatorData.credentialPublicKey ? 
          authenticatorData.credentialPublicKey.slice(0, 32).toString('hex') : 'null',
        fullType: Object.prototype.toString.call(authenticatorData.credentialPublicKey),
        hasGetMethod: typeof authenticatorData.credentialPublicKey?.get === 'function',
        prototypeChain: Object.getPrototypeOf(authenticatorData.credentialPublicKey || {})?.constructor?.name
      },
      counter: authenticatorData.counter,
      transports: authenticatorData.transports
    };
    
    logger.debug('authenticatorData:', authData);
    
    // Debug: Try to decode the public key to see its structure
    if (authenticatorData.credentialPublicKey && Buffer.isBuffer(authenticatorData.credentialPublicKey)) {
      try {
        const decoded = cbor.decodeFirstSync(authenticatorData.credentialPublicKey);
        logger.debug('=== Decoded Public Key Structure ===');
        logger.debug(JSON.stringify(decoded, (key, value) => {
          if (value instanceof Map) {
            return Object.fromEntries(value);
          }
          return value;
        }, 2));
      } catch (e) {
        logger.debug('Failed to decode public key as CBOR:', e.message);
      }
    }
    
    // Log the full public key in hex for debugging
    if (credentialPublicKey) {
      logger.debug('Full credentialPublicKey hex (first 100 chars):', 
        credentialPublicKey.toString('hex').substring(0, 100) + '...');
    }
    
    // Validate the credentialPublicKey structure
    try {
      if (!credentialPublicKey || !Buffer.isBuffer(credentialPublicKey)) {
        throw new WebAuthnError('Invalid public key: must be a Buffer', 'INVALID_PUBLIC_KEY');
      }
      
      // Try to decode the COSE key to ensure it's valid
      try {
        const decodedKey = cbor.decodeFirstSync(credentialPublicKey);
        logger.debug('Successfully decoded COSE key structure:', JSON.stringify(decodedKey, null, 2));
        
        // Ensure all required COSE key fields are present
        const requiredCoseFields = [1, 3, -1, -2, -3]; // kty, alg, crv, x, y
        const missingFields = requiredCoseFields.filter(field => !decodedKey.has(field));
        
        if (missingFields.length > 0) {
          throw new WebAuthnError(
            `Missing required COSE key fields: ${missingFields.join(', ')}`,
            'INVALID_PUBLIC_KEY'
          );
        }
      } catch (decodeError) {
        console.error('Failed to decode COSE key:', decodeError);
        throw new WebAuthnError('Invalid COSE key format', 'INVALID_PUBLIC_KEY');
      }
      
      // Ensure authenticatorData has all required properties
      const requiredProps = {
        credentialID: 'Buffer',
        credentialPublicKey: 'Buffer',
        counter: 'number',
        transports: 'object'
      };
      
      const missingProps = [];
      const invalidProps = [];
      
      for (const [prop, type] of Object.entries(requiredProps)) {
        if (!(prop in authenticatorData)) {
          missingProps.push(prop);
        } else if (type === 'Buffer' && !Buffer.isBuffer(authenticatorData[prop])) {
          invalidProps.push(`${prop} (expected Buffer, got ${typeof authenticatorData[prop]})`);
        } else if (type === 'number' && typeof authenticatorData[prop] !== 'number') {
          invalidProps.push(`${prop} (expected number, got ${typeof authenticatorData[prop]})`);
        } else if (type === 'object' && !Array.isArray(authenticatorData[prop])) {
          invalidProps.push(`${prop} (expected Array, got ${typeof authenticatorData[prop]})`);
        }
      }
      
      if (missingProps.length > 0 || invalidProps.length > 0) {
        const errors = [
          ...missingProps.map(p => `Missing required property: ${p}`),
          ...invalidProps.map(p => `Invalid property: ${p}`)
        ];
        console.error('Invalid authenticator object:', { 
          missingProps, 
          invalidProps,
          authenticatorData: {
            ...authenticatorData,
            credentialID: authenticatorData.credentialID ? 
              `[Buffer ${authenticatorData.credentialID.length} bytes]` : 'null',
            credentialPublicKey: authenticatorData.credentialPublicKey ? 
              `[Buffer ${authenticatorData.credentialPublicKey.length} bytes]` : 'null'
          }
        });
        throw new WebAuthnError(
          `Invalid authenticator data: ${errors.join('; ')}`,
          'INVALID_AUTHENTICATOR_DATA'
        );
      }
      
      // Prepare the authenticator object for verification
      const verificationAuthenticator = {
        ...authenticatorData,
        credentialPublicKey: credentialPublicKey // Ensure we use the validated key
      };
      
      logger.debug('=== Calling verifyAuthenticationResponse ===');
      const verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge: expectedChallenge,
        expectedOrigin,
        expectedRPID,
        authenticator: verificationAuthenticator,
        requireUserVerification
      });
      
      logger.debug('Verification result:', {
        verified: verification.verified,
        authenticationInfo: verification.authenticationInfo ? {
          newCounter: verification.authenticationInfo.newCounter,
          credentialID: verification.authenticationInfo.credentialID ? 
            `[Buffer ${verification.authenticationInfo.credentialID.length} bytes]` : 'null'
        } : null
      });
      
      return verification;
    } catch (error) {
      console.error('Error in verifyAuthenticationResponse:', error);
      console.error('Error stack:', error.stack);
      throw error;
    }
    
    const { verified, authenticationInfo } = verification;
    
    if (verified && authenticationInfo) {
      // Update the authenticator's counter
      await updateAuthenticatorCounter(authenticator.id, authenticationInfo.newCounter);
      
      // Clear the challenge
      await clearChallenge(userId.toString('hex'), 'authentication');
    }
    
    return {
      verified,
      authenticationInfo: verified ? authenticationInfo : null,
      error: verified ? null : 'Authentication verification failed'
    };
  } catch (error) {
    if (error instanceof WebAuthnError) throw error;
    console.error('Error during authentication verification:', error);
    throw new WebAuthnError('Authentication failed', 'AUTHENTICATION_FAILED');
  }
}

/**
 * Store a WebAuthn challenge in the database
 * @param {string} userId - User ID (UUID string)
 * @param {string} challenge - The challenge to store
 * @param {string} type - Challenge type ('registration' or 'authentication')
 * @returns {Promise<void>}
 */
async function storeChallenge(userId, challenge, type) {
  if (!userId || typeof userId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId)) {
    throw new WebAuthnError('Invalid user ID format', 'INVALID_USER_ID');
  }
  
  if (!challenge || typeof challenge !== 'string') {
    throw new WebAuthnError('Invalid challenge', 'INVALID_CHALLENGE');
  }
  
  if (!['registration', 'authentication'].includes(type)) {
    throw new WebAuthnError('Invalid challenge type', 'INVALID_CHALLENGE_TYPE');
  }

  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Delete any existing challenge for this user and type
    await client.query(
      'DELETE FROM webauthn_challenges WHERE user_id = $1::uuid AND type = $2',
      [userId, type]
    );
    
    // Insert new challenge with expiration (10 minutes from now)
    await client.query(
      `INSERT INTO webauthn_challenges (user_id, challenge, type, expires_at) 
       VALUES ($1::uuid, $2, $3, NOW() + INTERVAL '10 minutes')`,
      [userId, challenge, type]
    );
    
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error storing WebAuthn challenge:', error);
    
    if (error instanceof WebAuthnError) {
      throw error;
    }
    
    throw new WebAuthnError(
      error.message ?? 'Failed to store challenge',
      'CHALLENGE_STORAGE_ERROR'
    );
  } finally {
    client.release();
  }
}

/**
 * Get a stored challenge from the database
 * @param {string} userId - User ID (UUID string)
 * @param {string} type - Challenge type ('registration' or 'authentication')
 * @returns {Promise<string|null>} The challenge string or null if not found or expired
 */
async function getChallenge(userId, type) {
  if (!userId || typeof userId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId)) {
    throw new WebAuthnError('Invalid user ID format', 'INVALID_USER_ID');
  }
  
  if (!['registration', 'authentication'].includes(type)) {
    throw new WebAuthnError('Invalid challenge type', 'INVALID_CHALLENGE_TYPE');
  }

  const client = await pool.connect();
  
  try {
    const result = await client.query(
      `SELECT challenge 
       FROM webauthn_challenges 
       WHERE user_id = $1::uuid 
         AND type = $2 
         AND expires_at > NOW()
       LIMIT 1`,
      [userId, type]
    );
    
    return result.rows[0] ? result.rows[0].challenge : null;
  } catch (error) {
    console.error('Error getting WebAuthn challenge:', error);
    
    if (error instanceof WebAuthnError) {
      throw error;
    }
    
    throw new WebAuthnError(
      error.message ?? 'Failed to get challenge',
      'CHALLENGE_RETRIEVAL_ERROR'
    );
  } finally {
    client.release();
  }
}

/**
 * Clear a stored challenge
 * @param {string} userId - User ID (UUID string)
 * @param {string} type - Challenge type ('registration' or 'authentication')
 * @returns {Promise<void>}
 */
async function clearChallenge(userId, type) {
  if (!userId || typeof userId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(userId)) {
    throw new WebAuthnError('Invalid user ID format', 'INVALID_USER_ID');
  }
  
  if (!['registration', 'authentication'].includes(type)) {
    throw new WebAuthnError('Invalid challenge type', 'INVALID_CHALLENGE_TYPE');
  }

  const client = await pool.connect();
  
  try {
    const result = await client.query(
      'DELETE FROM webauthn_challenges WHERE user_id = $1::uuid AND type = $2',
      [userId, type]
    );
    
    if (result.rowCount === 0) {
      logger.debug(`No challenge found to clear for user ${userId} and type ${type}`);
    }
  } catch (error) {
    console.error('Error clearing WebAuthn challenge:', error);
    
    if (error instanceof WebAuthnError) {
      throw error;
    }
    
    throw new WebAuthnError(
      error.message ?? 'Failed to clear challenge',
      'CHALLENGE_CLEAR_ERROR'
    );
  } finally {
    client.release();
  }
}

/**
 * Parse authenticator data buffer
 * @param {Buffer} buffer - Authenticator data buffer
 * @returns {Object} Parsed authenticator data
 */
function parseAuthenticatorData(buffer) {
  let offset = 0;
  
  // Parse the first 32 bytes (RP ID hash)
  const rpIdHash = buffer.slice(offset, offset + 32);
  offset += 32;
  
  // Parse flags
  const flags = buffer[offset++];
  
  // Parse counters
  const signCount = buffer.readUInt32BE(offset);
  offset += 4;
  
  let attestedCredentialData = null;
  let extensionsData = null;
  
  // Check if attested credential data is present
  if (flags & 0x40) { // AT flag
    // Parse AAGUID (16 bytes)
    const aaguid = buffer.slice(offset, offset + 16);
    offset += 16;
    
    // Parse credential ID length (2 bytes, big-endian)
    const credentialIdLength = buffer.readUInt16BE(offset);
    offset += 2;
    
    // Parse credential ID
    const credentialId = buffer.slice(offset, offset + credentialIdLength);
    offset += credentialIdLength;
    
    // Parse credential public key (COSE_Key format)
    const publicKeyCose = buffer.slice(offset);
    
    attestedCredentialData = {
      aaguid,
      credentialId,
      credentialPublicKey: publicKeyCose
    };
    
    // Update offset to the end of the public key
    offset += publicKeyCose.length;
  }
  
  // Check if extension data is present
  if (flags & 0x80) { // ED flag
    const extensionData = buffer.slice(offset);
    extensionsData = extensionData;
  }
  
  return {
    rpIdHash,
    flags: {
      up: !!(flags & 0x01),  // User Present
      uv: !!(flags & 0x04),  // User Verified
      at: !!(flags & 0x40),  // Attested Credential Data
      ed: !!(flags & 0x80)   // Extension Data
    },
    signCount,
    attestedCredentialData,
    extensionsData
  };
}

/**
 * Log the structure of a COSE public key for debugging
 * @param {Buffer} publicKey - The public key to analyze
 */
function logCoseKeyStructure(publicKey) {
  if (!publicKey || !Buffer.isBuffer(publicKey)) {
    logger.debug('Public key is not a Buffer');
    return;
  }

  logger.debug('Public key buffer length:', publicKey.length);
  logger.debug('First 32 bytes of public key:', publicKey.toString('hex').substring(0, 64) + '...');
  
  try {
    // Try to parse as COSE key
    const coseKey = isoCBOR.decode(publicKey);
    logger.debug('Parsed COSE key structure:', JSON.stringify(coseKey, null, 2));
    
    // Check for required COSE key fields
    if (coseKey) {
      logger.debug('COSE Key Type (kty):', coseKey[1] ?? 'Not found');
      logger.debug('Algorithm (alg):', coseKey[3] ?? 'Not found');
      
      // For EC2 keys
      if (coseKey[-1] === 2) { // EC2 key type
        logger.debug('EC2 Curve:', coseKey[-1] ?? 'Not found');
        logger.debug('X coordinate present:', !!coseKey[-2]);
        logger.debug('Y coordinate present:', !!coseKey[-3]);
      }
      // For RSA keys
      else if (coseKey[-1] === 3) {
        logger.debug('RSA Modulus (n) present:', !!coseKey[-1]);
        logger.debug('RSA Public Exponent (e) present:', !!coseKey[-2]);
      }
    }
  } catch (error) {
    logger.debug('Could not parse as COSE key. Raw bytes:', publicKey.toString('hex'));
  }
}

/**
 * Attempt to fix a potentially malformed COSE public key
 * @param {Buffer} publicKey - The public key to fix
 * @returns {Buffer} The fixed public key
 */
function fixMalformedCoseKey(publicKey) {
  logger.debug('Attempting to fix malformed COSE key...');
  
  // Check if the key is in raw format (common issue)
  // A raw EC public key is typically 65 bytes (uncompressed) or 33 bytes (compressed)
  if (publicKey.length === 65 || publicKey.length === 33) {
    logger.debug('Detected raw EC public key, converting to COSE format...');
    // This is likely a raw EC public key, we need to convert it to COSE format
    // COSE EC2 key format:
    // Map {
    //   1: 2,  // kty: EC2 key type
    //   3: -7,  // alg: ES256
    //   -1: 1,  // crv: P-256
    //   -2: x,  // x-coordinate
    //   -3: y   // y-coordinate (for uncompressed keys)
    // }
    
    try {
      const coseKey = new Map();
      coseKey.set(1, 2); // kty: EC2 key type
      coseKey.set(3, -7); // alg: ES256
      coseKey.set(-1, 1); // crv: P-256
      
      if (publicKey.length === 65) {
        // Uncompressed format (0x04 + x + y)
        if (publicKey[0] === 0x04) {
          const x = publicKey.slice(1, 33);
          const y = publicKey.slice(33);
          coseKey.set(-2, x); // x-coordinate
          coseKey.set(-3, y); // y-coordinate
          logger.debug('Converted uncompressed EC key to COSE format');
          return Buffer.from(isoCBOR.encode(coseKey));
        }
      } else if (publicKey.length === 33) {
        // Compressed format (0x02 or 0x03 + x)
        if (publicKey[0] === 0x02 || publicKey[0] === 0x03) {
          const x = publicKey.slice(1);
          coseKey.set(-2, x); // x-coordinate
          // Note: For compressed keys, y-coordinate is derived from x and the sign bit
          logger.debug('Converted compressed EC key to COSE format (y-coordinate will be derived)');
          return Buffer.from(isoCBOR.encode(coseKey));
        }
      }
    } catch (fixError) {
      console.error('Error fixing malformed COSE key:', fixError);
      throw new Error('Failed to fix malformed COSE key: ' + fixError.message);
    }
  }
  
  // If we can't fix it, return the original
  logger.debug('Could not automatically fix the COSE key format');
  return publicKey;
}

/**
 * Verify and normalize the COSE public key structure
 * @param {Buffer} publicKey - The public key to verify
 * @returns {Buffer} The normalized public key
 */
function verifyAndNormalizePublicKey(publicKey) {
  if (!publicKey || !Buffer.isBuffer(publicKey)) {
    throw new Error('Public key must be a Buffer');
  }

  // Log the key structure before processing
  logger.debug('=== Public Key Analysis ===');
  logCoseKeyStructure(publicKey);
  
  try {
    // Step 0: If the Buffer actually contains ASCII-hex or base64/base64url text, convert to binary
    try {
      const text = publicKey.toString('utf8').trim();
      // Hex
      if (/^[0-9a-fA-F]+$/.test(text) && text.length % 2 === 0) {
        const hexBuf = Buffer.from(text, 'hex');
        if (hexBuf.length > 0) {
          logger.debug('verifyAndNormalizePublicKey: converted ASCII-hex Buffer to binary');
          publicKey = hexBuf;
        }
      } else {
        // Base64 or Base64url
        let b64Text = text;
        if (/^[A-Za-z0-9_\-]+$/.test(text) && text.length % 4 !== 0) {
          // Likely base64url without padding; normalize to base64
          b64Text = text.replace(/-/g, '+').replace(/_/g, '/');
          while (b64Text.length % 4 !== 0) b64Text += '=';
        }
        if (/^[A-Za-z0-9+/=]+$/.test(b64Text)) {
          try {
            const b64Buf = Buffer.from(b64Text, 'base64');
            // Heuristic: only accept if non-trivial
            if (b64Buf && b64Buf.length > 0) {
              logger.debug('verifyAndNormalizePublicKey: converted base64/base64url Buffer text to binary');
              publicKey = b64Buf;
            }
          } catch {}
        }
      }
    } catch {}

    // First try to parse as-is
    try {
      const coseKey = cbor.decodeFirstSync(publicKey);
      const normalized = cbor.encodeCanonical(coseKey);
      const result = Buffer.from(normalized);
      logger.debug('Public key verified and normalized successfully');
      return result;
    } catch (initialError) {
      logger.debug('decodeFirstSync failed, attempting to fix or fallback. Reason:', initialError?.message || initialError);

      // Attempt to fix malformed COSE key (raw EC or compressed)
      const fixedKey = fixMalformedCoseKey(publicKey);
      if (fixedKey && fixedKey !== publicKey) {
        logger.debug('Key was fixed, attempting to parse fixed key...');
        const coseKey = cbor.decodeFirstSync(fixedKey);
        const normalized = cbor.encodeCanonical(coseKey);
        const result = Buffer.from(normalized);
        logger.debug('Successfully normalized fixed public key');
        return result;
      }
      
      // Fallback: Some authenticators append trailing CBOR data; try decodeAllSync and take first item
      try {
        const items = cbor.decodeAllSync(publicKey);
        if (Array.isArray(items) && items.length > 0) {
          logger.debug('decodeAllSync succeeded with', items.length, 'items; using the first one');
          const normalized = cbor.encodeCanonical(items[0]);
          return Buffer.from(normalized);
        }
      } catch (allErr) {
        logger.debug('decodeAllSync fallback failed:', allErr?.message || allErr);
      }
      
      // If we couldn't fix it, rethrow the original error
      throw initialError;
    }
  } catch (error) {
    console.error('Error processing COSE public key:', error);
    throw new Error('Invalid COSE public key format: ' + (error?.message || error));
  }
}

export {
  generateWebAuthnRegistrationOptions,
  verifyRegistration,
  generateWebAuthnAuthenticationOptions,
  verifyAuthentication,
  storeChallenge,
  getChallenge,
  clearChallenge,
  parseAuthenticatorData,
  normalizeDisplayName,
  verifyAndNormalizePublicKey,
  WebAuthnError
};
