import express from 'express';
import passport from 'passport';
import crypto from 'crypto';
import {
  generateWebAuthnRegistrationOptions,
  verifyRegistration,
  generateWebAuthnAuthenticationOptions,
  verifyAuthentication,
  WebAuthnError
} from '../utils/webauthn.js';
import JSZip from 'jszip';
import { generateFidoStub, detectKeyTypeFromCOSE } from '../utils/sshKeys.js';
import { generateTotpSecret, verifyTotpCode } from '../utils/totp.js';
import emailService from '../services/emailService.js';
import { getAuthenticatorByUserId, deleteAuthenticator, renameAuthenticator, getAuthenticatorByCredentialId, updateAuthenticator } from '../db/authenticatorOps.js';
import { getUserById, getUserByUsername } from '../db/userOps.js';
import { v4 as uuidv4 } from 'uuid';
import pool from '../db/index.js';
import { clearChallenge } from '../utils/webauthn.js';
import { logger } from '../utils/logger.js';

const router = express.Router();

// Middleware to validate UUID format, with fallback resolution by username
const validateUserId = async (req, res, next) => {
  logger.debug('Session user object:', JSON.stringify(req.user, null, 2));
  const userId = req.user?.user_id || req.user?.id;
  logger.debug('Extracted userId:', userId);
  
  if (!userId) {
    console.error('No user ID found in session');
    return res.status(400).json({
      error: 'User ID not found in session',
      code: 'MISSING_USER_ID'
    });
  }
  
  if (typeof userId !== 'string') {
    console.error('User ID is not a string:', typeof userId, userId);
    return res.status(400).json({
      error: 'User ID must be a string',
      code: 'INVALID_USER_ID_TYPE'
    });
  }
  
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(userId)) {
    console.warn('Invalid UUID format in session, attempting resolution by username:', userId);
    try {
      const username = req.user?.username;
      if (!username) {
        console.error('Cannot resolve user ID: missing username in session');
        return res.status(400).json({
          error: 'Invalid user ID format',
          code: 'INVALID_USER_ID',
          receivedId: userId
        });
      }

      const dbUser = await getUserByUsername(username);
      if (!dbUser?.id) {
        console.error('Cannot resolve user ID: username not found in DB:', username);
        return res.status(400).json({
          error: 'Invalid user ID format',
          code: 'INVALID_USER_ID',
          receivedId: userId
        });
      }

      // Patch req.user with correct UUID so downstream handlers work
      req.user.user_id = dbUser.id;
      req.user.id = dbUser.id;
      logger.debug('Resolved user ID from username. Patched session user to UUID:', dbUser.id);
      return next();
    } catch (e) {
      console.error('Error resolving user ID by username:', e);
      return res.status(400).json({
        error: 'Invalid user ID format',
        code: 'INVALID_USER_ID',
        receivedId: userId
      });
    }
  }
  
  next();
};

// Middleware to check if user is authenticated using session
const requireAuth = (req, res, next) => {
  logger.debug('Session:', req.session);
  logger.debug('User:', req.user);
  logger.debug('isAuthenticated:', req.isAuthenticated ? req.isAuthenticated() : 'undefined');
  
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  
  if (req.xhr || req.headers.accept?.includes('application/json')) {
    return res.status(401).json({ 
      error: 'Not authenticated', 
      code: 'NOT_AUTHENTICATED' 
    });
  }
  
  res.redirect('/login');
};

// In-memory store for rate limiting
const totpAttempts = new Map();
const MAX_ATTEMPTS = 5;
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Check and update rate limiting for TOTP attempts
 * @param {string} userId - User ID to check
 * @returns {{allowed: boolean, remaining: number}} - Whether the attempt is allowed and remaining attempts
 */
function checkRateLimit(userId) {
  const now = Date.now();
  const attempts = totpAttempts.get(userId) || [];
  
  // Filter out attempts older than the time window
  const recentAttempts = attempts.filter(timestamp => now - timestamp < ATTEMPT_WINDOW_MS);
  
  // Update the attempts
  recentAttempts.push(now);
  totpAttempts.set(userId, recentAttempts);
  
  const remaining = Math.max(0, MAX_ATTEMPTS - recentAttempts.length);
  return {
    allowed: recentAttempts.length <= MAX_ATTEMPTS,
    remaining,
    retryAfter: recentAttempts.length >= MAX_ATTEMPTS ? 
      Math.ceil((recentAttempts[0] + ATTEMPT_WINDOW_MS - now) / 1000) : 0
  };
}

/**
 * @route POST /api/webauthn/register/init
 * @desc Initialize WebAuthn registration
 * @access Private (requires session auth)
 */
router.post('/register/init', requireAuth, validateUserId, async (req, res, next) => {
  try {
    const userId = req.user.user_id || req.user.id;
    
    // Check if user already has an authenticator
    const existingAuth = await getAuthenticatorByUserId(userId);
    if (existingAuth) {
      return res.status(400).json({ 
        error: 'Authenticator already registered', 
        code: 'AUTHENTICATOR_EXISTS' 
      });
    }

    // Get user details
    const user = await getUserById(userId);
    if (!user) {
      return res.status(404).json({ 
        error: 'User not found', 
        code: 'USER_NOT_FOUND' 
      });
    }

    // Generate TOTP secret and send email
    const { code, token } = generateTotpSecret(userId);
    
    console.log('Generated TOTP code:', code);
    console.log('Generated TOTP token:', token);

    // Send TOTP code to user's email if SMTP is enabled
    if (process.env.SMTP_ENABLED && process.env.SMTP_ENABLED.toLowerCase() === 'true') {
      await emailService.sendTotpEmail(user.email, code);
    }

    res.json({ 
      message: 'TOTP sent to your email',
      token // This token must be used in the next step to verify TOTP
    });
  } catch (error) {
    console.error('Error initializing registration:', error);
    next(error);
  }
});

/**
 * @route POST /api/webauthn/verify-totp
 * @desc Verify TOTP code and return WebAuthn registration options if valid
 * @access Private (requires session auth)
 */
router.post('/verify-totp', requireAuth, validateUserId, async (req, res, next) => {
  try {
    console.log('TOTP Verification Request Body:', JSON.stringify(req.body, null, 2));
    console.log('Session User:', JSON.stringify(req.user, null, 2));
    
    const { token, code } = req.body;
    const userId = req.user?.user_id || req.user?.id;

    // Input validation
    if (!token || !code) {
      console.error('Missing required fields:', { token: !!token, code: !!code });
      return res.status(400).json({ 
        error: 'Token and code are required', 
        code: 'MISSING_FIELDS' 
      });
    }

    // Check rate limiting
    const rateLimit = checkRateLimit(userId);
    if (!rateLimit.allowed) {
      console.error(`Rate limit exceeded for user ${userId}`);
      return res.status(429).json({
        error: 'Too many attempts. Please try again later.',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: rateLimit.retryAfter
      });
    }

    // Verify TOTP code
    console.log('Verifying TOTP code...');
    const { valid, userId: verifiedUserId } = verifyTotpCode(token, code);
    
    if (!valid) {
      console.error('Invalid or expired TOTP code');
      return res.status(400).json({ 
        error: 'Invalid or expired code', 
        code: 'INVALID_TOTP',
        remainingAttempts: rateLimit.remaining - 1
      });
    }
    
    // Verify the user ID from TOTP matches the session user ID
    if (verifiedUserId !== userId) {
      console.error('User ID mismatch between session and TOTP verification');
      return res.status(403).json({
        error: 'Invalid user session',
        code: 'INVALID_SESSION'
      });
    }

    // Clear successful attempts
    totpAttempts.delete(userId);
    
    // Get user details
    console.log('Fetching user details for ID:', userId);
    const user = await getUserById(userId);
    if (!user) {
      console.error('User not found in database');
      return res.status(404).json({ 
        error: 'User not found', 
        code: 'USER_NOT_FOUND' 
      });
    }

    // Ensure we have a valid user ID
    if (!userId) {
      console.error('No user ID found in session');
      return res.status(400).json({
        error: 'User session is invalid',
        code: 'INVALID_SESSION'
      });
    }

    // Generate WebAuthn registration options
    console.log('Generating WebAuthn registration options...');
    try {
      // Ensure we have a valid display name
      const displayName = user.displayName || user.username || `User-${userId.substring(0, 8)}`;
      
      console.log('Using display name for registration:', displayName);
      
      const options = await generateWebAuthnRegistrationOptions(
        userId,
        user.username,
        displayName
      );
      
      console.log('TOTP verification successful, returning registration options');
      
      // Log the options being sent to the client
      console.log('Registration options:', JSON.stringify({
        ...options,
        user: {
          ...options.user,
          id: '***',
          name: options.user.name,
          displayName: options.user.displayName
        },
        challenge: '***'
      }, null, 2));
      
      // Wrap options in optionsJSON property for client compatibility
      res.json({
        optionsJSON: JSON.stringify(options, (key, value) => 
          value instanceof Buffer ? Array.from(value) : value
        ),
        ...options
      });
    } catch (error) {
      console.error('Error generating WebAuthn registration options:', error);
      return res.status(500).json({
        error: 'Failed to generate registration options',
        code: 'REGISTRATION_ERROR',
        details: error.message
      });
    }
  } catch (error) {
    console.error('TOTP Verification Error:', error);
    next(error);
  }
});

/**
 * @route POST /api/webauthn/register/verify
 * @desc Complete WebAuthn registration
 * @access Private (requires session auth)
 */
router.post('/register/verify', requireAuth, validateUserId, async (req, res, next) => {
  try {
    console.log('Received registration verification request:', {
      body: req.body ? {
        credential: {
          id: req.body.credential?.id ? 'present' : 'missing',
          type: req.body.credential?.type || 'missing',
          rawId: req.body.credential?.rawId ? 'present' : 'missing',
          response: req.body.credential?.response ? {
            attestationObject: req.body.credential.response.attestationObject ? 'present' : 'missing',
            clientDataJSON: req.body.credential.response.clientDataJSON ? 'present' : 'missing'
          } : 'missing'
        },
        name: req.body.name ? 'present' : 'missing'
      } : 'no body',
      user: req.user ? { id: req.user.user_id || req.user.id } : 'no user'
    });
    
    const { credential, name } = req.body;
    const userId = req.user.user_id || req.user.id;
    
    try {
      // Get user details to ensure we have the latest display name
      const user = await getUserById(userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
      }
      
      // Ensure we have a valid display name with proper encoding
      const displayName = (user.displayName || user.username || `User-${userId.substring(0, 8)}`).normalize('NFC');
      
      // Verify registration with the user's display name
      console.log('Using display name for WebAuthn registration:', displayName);
      const verification = await verifyRegistration({
        credential,
        expectedOrigin: process.env.FIDO2_RP_ORIGIN || `https://${process.env.DOMAIN || 'localhost'}`,
        expectedRPID: process.env.FIDO2_RP_ID || 'localhost',
        requireUserVerification: true,
        name: name || `${displayName}'s Security Key`,
        userDisplayName: displayName
      }, userId);
      
      if (!verification.verified) {
        return res.status(400).json({
          error: 'Registration verification failed',
          code: 'VERIFICATION_FAILED',
          details: verification.error
        });
      }
      
      res.status(200).json({ 
        verified: true,
        message: 'WebAuthn registration successful',
        authenticator: {
          id: verification.authenticator.id,
          name: verification.authenticator.name,
          createdAt: verification.authenticator.created_at,
          credential_id: verification.authenticator.credential_id
        }
      });
    } catch (error) {
      console.error('Registration verification error:', error);
      if (error instanceof WebAuthnError) {
        return res.status(400).json({
          error: error.message,
          code: error.code || 'VERIFICATION_ERROR',
          details: error.details
        });
      }
      throw error;
    }
  } catch (error) {
    console.error('Error in registration verification:', error);
    next(error);
  }
});

/**
 * @route POST /api/webauthn/authenticate/init
 * @desc Get WebAuthn authentication options
 * @access Private (requires session auth)
 */
router.post('/authenticate/init', requireAuth, validateUserId, async (req, res, next) => {
  try {
    const userId = req.user.user_id || req.user.id;
    
    // Generate authentication options
    const options = await generateWebAuthnAuthenticationOptions({
      rpID: process.env.FIDO2_RP_ID,
      userVerification: 'required',
      timeout: 60000
    });
    
    res.status(200).json({
      success: true,
      data: options
    });
  } catch (error) {
    console.error('Error generating authentication options:', error);
    
    if (error instanceof WebAuthnError) {
      return res.status(400).json({ 
        error: error.message, 
        code: error.code 
      });
    }
    
    res.status(500).json({
      error: 'Failed to generate authentication options',
      code: 'AUTH_OPTIONS_ERROR'
    });
  }
});

/**
 * @route POST /api/webauthn/register/finalize
 * @desc Finalize WebAuthn registration (set name and clear challenge)
 * @access Private (requires session auth)
 */
router.post('/register/finalize', requireAuth, validateUserId, async (req, res, next) => {
  try {
    const { name, credentialId } = req.body;
    const userId = req.user.user_id || req.user.id;
    
    if (!name) {
      return res.status(400).json({ 
        error: 'Name is required',
        code: 'NAME_REQUIRED'
      });
    }
    
    if (!credentialId) {
      return res.status(400).json({ 
        error: 'Credential ID is required',
        code: 'CREDENTIAL_ID_REQUIRED'
      });
    }
    
    // Get the authenticator by credential ID
    const authenticator = await getAuthenticatorByCredentialId(credentialId);
    
    if (!authenticator) {
      return res.status(404).json({
        error: 'Authenticator not found',
        code: 'AUTHENTICATOR_NOT_FOUND'
      });
    }
    
    // Verify the authenticator belongs to the current user
    if (authenticator.user_id !== userId) {
      return res.status(403).json({
        error: 'Not authorized to update this authenticator',
        code: 'UNAUTHORIZED'
      });
    }
    
    // Update the authenticator name
    await updateAuthenticator(authenticator.id, { name });
    
    // Clear the registration challenge
    await clearChallenge(userId, 'registration');
    
    res.status(200).json({ 
      success: true,
      authenticator: {
        id: authenticator.id,
        name: name,
        credential_id: authenticator.credential_id,
        created_at: authenticator.created_at
      }
    });
  } catch (error) {
    console.error('Error finalizing registration:', error);
    
    if (error.code) {
      return res.status(400).json({
        error: error.message,
        code: error.code
      });
    }
    
    res.status(500).json({
      error: 'Failed to finalize registration',
      code: 'FINALIZATION_ERROR'
    });
  }
});

/**
 * @route POST /api/webauthn/authenticate/verify
 * @desc Verify WebAuthn authentication
 * @access Private (requires session auth)
 */
router.post('/authenticate/verify', requireAuth, validateUserId, async (req, res, next) => {
  try {
    const { credential } = req.body;
    const userId = req.user.user_id || req.user.id;

    if (!credential) {
      return res.status(400).json({ 
        error: 'Credential is required', 
        code: 'MISSING_CREDENTIAL' 
      });
    }

    // Verify WebAuthn authentication
    const verification = await verifyAuthentication({
      credential,
      expectedOrigin: process.env.FIDO2_RP_ORIGIN,
      expectedRPID: process.env.FIDO2_RP_ID,
      requireUserVerification: true
    }, userId);

    if (!verification.verified) {
      return res.status(400).json({
        error: 'Authentication verification failed',
        code: 'VERIFICATION_FAILED',
        details: verification.error
      });
    }

    // Update user's last login timestamp
    try {
      await pool.query(
        'UPDATE users SET last_login = NOW() WHERE id = $1::uuid',
        [userId]
      );
    } catch (dbError) {
      console.error('Error updating last login timestamp:', dbError);
      // Continue even if we can't update the timestamp
    }

    res.status(200).json({ 
      success: true, 
      message: 'Authentication successful',
      user: {
        id: userId,
        username: req.user.username
      }
    });
  } catch (error) {
    console.error('Error during authentication verification:', error);
    
    if (error instanceof WebAuthnError) {
      return res.status(400).json({ 
        error: error.message, 
        code: error.code 
      });
    }
    
    res.status(500).json({
      error: 'Authentication verification failed',
      code: 'AUTH_VERIFICATION_ERROR'
    });
  }
});

/**
 * @route GET /api/webauthn/credentials
 * @desc Get user's registered authenticator
 * @access Private (requires session auth)
 */
router.get('/credentials', requireAuth, validateUserId, async (req, res, next) => {
  try {
    const userId = req.user.user_id || req.user.id;
    const authenticator = await getAuthenticatorByUserId(userId);
    
    if (!authenticator) {
      return res.status(404).json({ 
        error: 'No authenticator found', 
        code: 'NO_AUTHENTICATOR' 
      });
    }

    // Return the authenticator in the expected format
    res.json({
      authenticator: {
        id: authenticator.id,
        credential_id: authenticator.credential_id,
        public_key: authenticator.public_key,
        counter: authenticator.counter,
        name: authenticator.name || 'Security Key',
        createdAt: authenticator.created_at,
        lastUsed: authenticator.last_used_at
      }
    });
    
  } catch (error) {
    console.error('Error getting authenticator:', error);
    
    if (error instanceof WebAuthnError) {
      return res.status(400).json({ 
        error: error.message, 
        code: error.code 
      });
    }
    
    res.status(500).json({
      error: 'Failed to get authenticator',
      code: 'AUTHENTICATOR_FETCH_ERROR'
    });
  }
});

/**
 * @route DELETE /api/webauthn/authenticator
 * @desc Delete user's authenticator
 * @access Private (requires session auth)
 */
router.delete('/authenticator', requireAuth, validateUserId, async (req, res, next) => {
  try {
    const userId = req.user.user_id || req.user.id;
    const success = await deleteAuthenticator(userId);
    
    if (!success) {
      return res.status(404).json({ 
        error: 'No authenticator found for user', 
        code: 'AUTHENTICATOR_NOT_FOUND' 
      });
    }
    
    res.status(200).json({ 
      success: true, 
      message: 'Authenticator removed successfully' 
    });
  } catch (error) {
    console.error('Error deleting authenticator:', error);
    
    if (error instanceof WebAuthnError) {
      return res.status(400).json({ 
        error: error.message, 
        code: error.code 
      });
    }
    
    res.status(500).json({
      error: 'Failed to remove authenticator',
      code: 'AUTHENTICATOR_DELETION_ERROR'
    });
  }
});

/**
 * @route PATCH /api/webauthn/authenticator/name
 * @desc Rename user's authenticator
 * @access Private (requires session auth)
 */
router.patch('/authenticator/name', requireAuth, validateUserId, async (req, res, next) => {
  try {
    const userId = req.user.user_id || req.user.id;
    const { name } = req.body;

    // Validate name input
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({
        error: 'Name is required and must be a non-empty string',
        code: 'INVALID_NAME'
      });
    }

    const trimmedName = name.trim();
    
    // Validate name length
    if (trimmedName.length > 50) {
      return res.status(400).json({
        error: 'Name must be 50 characters or less',
        code: 'NAME_TOO_LONG'
      });
    }

    // Rename the authenticator
    const authenticator = await renameAuthenticator(userId, trimmedName);
    
    if (!authenticator) {
      return res.status(404).json({
        error: 'No authenticator found for user',
        code: 'AUTHENTICATOR_NOT_FOUND'
      });
    }
    
    res.status(200).json({ 
      success: true, 
      message: 'Authenticator renamed successfully',
      name: authenticator.name
    });
  } catch (error) {
    console.error('Error renaming authenticator:', error);
    
    if (error.code === 'AUTHENTICATOR_NOT_FOUND' || error.message.includes('not found')) {
      return res.status(404).json({ 
        error: 'No authenticator found for user', 
        code: 'AUTHENTICATOR_NOT_FOUND' 
      });
    }
    
    res.status(500).json({
      error: 'Failed to rename authenticator',
      code: 'AUTHENTICATOR_RENAME_ERROR'
    });
  }
});

/**
 * @route GET /api/webauthn/ssh/stub/:credentialId
 * @desc Download a ZIP containing only the SSH FIDO stub private key
 * @access Private (requires session auth)
 */
router.get('/ssh/stub/:credentialId', requireAuth, validateUserId, async (req, res, next) => {
  try {
    const userId = req.user.user_id || req.user.id;
    const { credentialId } = req.params;

    if (!credentialId) {
      return res.status(400).json({ error: 'Credential ID is required', code: 'CREDENTIAL_ID_REQUIRED' });
    }

    // Load authenticator and ensure ownership
    const auth = await getAuthenticatorByCredentialId(credentialId);
    if (!auth) {
      return res.status(404).json({ error: 'Authenticator not found', code: 'AUTHENTICATOR_NOT_FOUND' });
    }
    if (auth.user_id !== userId) {
      return res.status(403).json({ error: 'Not authorized to access this authenticator', code: 'UNAUTHORIZED' });
    }

    // Determine key type and normalize to OpenSSH sk types
    let keyType = auth.ssh_key_type;
    try {
      if (!keyType && auth.credential_public_key) {
        keyType = detectKeyTypeFromCOSE(auth.credential_public_key);
      }
    } catch (e) {
      // ignore, will be handled below
    }
    const normalizeKeyType = (kt) => {
      if (!kt) return null;
      const s = String(kt).toLowerCase();
      if (s.includes('ed25519')) return 'sk-ssh-ed25519@openssh.com';
      if (s.includes('ecdsa') || s.includes('nistp256')) return 'sk-ecdsa-sha2-nistp256@openssh.com';
      if (s.includes('sk-ecdsa-sha2-nistp256@openssh.com')) return 'sk-ecdsa-sha2-nistp256@openssh.com';
      if (s.includes('sk-ssh-ed25519@openssh.com')) return 'sk-ssh-ed25519@openssh.com';
      return null;
    };
    let normalizedKeyType = normalizeKeyType(keyType);
    if (!normalizedKeyType && auth.credential_public_key) {
      try {
        const detected = detectKeyTypeFromCOSE(auth.credential_public_key);
        normalizedKeyType = normalizeKeyType(detected) || detected;
      } catch (e) {
        // ignore
      }
    }
    if (!normalizedKeyType) {
      return res.status(400).json({ error: 'Unable to determine SSH key type', code: 'UNKNOWN_KEY_TYPE' });
    }

    const domainFromBase = (() => {
      const base = process.env.LDAP_SEARCH_BASE_USERS || process.env.LDAP_SEARCH_BASE || 'dc=example,dc=org';
      const parts = base.match(/dc=([^,]+)/gi);
      if (parts && parts.length) return parts.map(p => p.split('=')[1]).join('.');
      return process.env.FIDO2_RP_ID || 'example.org';
    })();
    const comment = auth.ssh_comment || `${auth.username || req.user.username}@${process.env.LDAP_DOMAIN || domainFromBase}`;

    // Generate stub file
    let stub;
    try {
      stub = generateFidoStub({ 
        rpId: process.env.FIDO2_RP_ID, 
        keyType: normalizedKeyType, 
        comment,
        cosePublicKey: auth.credential_public_key,
        credentialId: auth.credential_id
      });
    } catch (e) {
      console.error('Stub ZIP generation error:', {
        message: e?.message,
        keyType: normalizedKeyType
      });
      return res.status(400).json({ error: e?.message || 'Stub generation failed', code: 'STUB_GENERATION_ERROR' });
    }

    // Build ZIP in-memory
    const zip = new JSZip();
    zip.file(stub.filename, stub.content);

    const zipBuf = await zip.generateAsync({ type: 'nodebuffer' });
    const dlName = `ssh-stub-${(auth.username || req.user.username)}-${new Date().toISOString().slice(0,10)}.zip`;
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${dlName}"`);
    return res.status(200).send(zipBuf);
  } catch (error) {
    console.error('Error generating SSH stub ZIP:', error);
    return res.status(500).json({ error: 'Failed to generate SSH stub ZIP', code: 'STUB_ZIP_ERROR' });
  }
});

/**
 * @route POST /api/webauthn/ssh/stub-token
 * @desc Generate a single-use token for SSH stub download
 * @access Private (requires session auth)
 */
router.post('/ssh/stub-token', requireAuth, validateUserId, async (req, res, next) => {
  try {
    const userId = req.user.user_id || req.user.id;
    const { credentialId } = req.body;

    if (!credentialId) {
      return res.status(400).json({ error: 'Credential ID is required', code: 'CREDENTIAL_ID_REQUIRED' });
    }

    // Load authenticator and ensure ownership
    const auth = await getAuthenticatorByCredentialId(credentialId);
    if (!auth) {
      return res.status(404).json({ error: 'Authenticator not found', code: 'AUTHENTICATOR_NOT_FOUND' });
    }
    if (auth.user_id !== userId) {
      return res.status(403).json({ error: 'Not authorized to access this authenticator', code: 'UNAUTHORIZED' });
    }

    // Generate random token (32 bytes = 64 hex chars)
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    console.log('[SSH UPLOAD] Token hash computed (sha256, first16):', tokenHash.slice(0, 16));
    
    // Token expires in 10 minutes
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    
    // Get client IP
    const issuerIp = req.ip || req.connection.remoteAddress || null;

    // Store token in database
    await pool.query(
      `INSERT INTO stub_tokens (token_hash, user_id, credential_id, expires_at, issuer_ip)
       VALUES ($1, $2, $3, $4, $5)`,
      [tokenHash, userId, credentialId, expiresAt, issuerIp]
    );

    // Build download URL to point directly to backend (no reverse proxy required)
    let downloadUrl;
    if (process.env.BACKEND_PUBLIC_URL) {
      const base = process.env.BACKEND_PUBLIC_URL.replace(/\/$/, '');
      downloadUrl = `${base}/api/webauthn/ssh/install?token=${token}`;
    } else if (process.env.FIDO2_RP_ID && process.env.SERVER_DEFAULT_PORT) {
      const host = process.env.FIDO2_RP_ID;
      const port = process.env.SERVER_DEFAULT_PORT;
      downloadUrl = `http://${host}:${port}/api/webauthn/ssh/install?token=${token}`;
    } else {
      // Fallback: derive host from request headers and enforce backend port
      let host = req.get('x-forwarded-host') || req.get('host') || 'localhost';
      host = host.split(':')[0];
      const port = process.env.SERVER_DEFAULT_PORT || '3000';
      downloadUrl = `http://${host}:${port}/api/webauthn/ssh/install?token=${token}`;
    }

    res.json({
      success: true,
      token,
      downloadUrl,
      expiresAt: expiresAt.toISOString(),
      expiresIn: '10 minutes'
    });
  } catch (error) {
    console.error('Error generating stub token:', error);
    return res.status(500).json({ error: 'Failed to generate download token', code: 'TOKEN_GENERATION_ERROR' });
  }
});

/**
 * @route GET /api/webauthn/ssh/stub/install
 * @desc Download SSH stub install script (single-use, token-based, no auth required)
 * @access Public (token-based)
 */
router.get('/ssh/install', async (req, res, next) => {
  try {
    const { token } = req.query;

    if (!token || typeof token !== 'string') {
      return res.status(400).type('text/plain').send('Error: Missing or invalid token');
    }

    // Hash the token to look it up
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Look up token
    const tokenResult = await pool.query(
      `SELECT id, user_id, credential_id, expires_at, used_at
       FROM stub_tokens
       WHERE token_hash = $1`,
      [tokenHash]
    );

    if (tokenResult.rows.length === 0) {
      return res.status(401).type('text/plain').send('Error: Invalid token');
    }

    const tokenRecord = tokenResult.rows[0];

    // Check if already used
    if (tokenRecord.used_at) {
      return res.status(410).type('text/plain').send('Error: Token already used');
    }

    // Check if expired
    if (new Date(tokenRecord.expires_at) < new Date()) {
      return res.status(401).type('text/plain').send('Error: Token expired');
    }

    // Mark token as used immediately
    await pool.query(
      `UPDATE stub_tokens SET used_at = NOW() WHERE id = $1`,
      [tokenRecord.id]
    );

    // Load authenticator
    const auth = await getAuthenticatorByCredentialId(tokenRecord.credential_id);
    if (!auth) {
      return res.status(404).type('text/plain').send('Error: Authenticator not found');
    }

    // Verify ownership matches token
    if (auth.user_id !== tokenRecord.user_id) {
      return res.status(403).type('text/plain').send('Error: Authorization mismatch');
    }

    // Determine key type and normalize to OpenSSH sk types
    let keyType = auth.ssh_key_type;
    const normalizeKeyType = (kt) => {
      if (!kt) return null;
      const s = String(kt).toLowerCase();
      if (s.includes('ed25519')) return 'sk-ssh-ed25519@openssh.com';
      if (s.includes('ecdsa') || s.includes('nistp256')) return 'sk-ecdsa-sha2-nistp256@openssh.com';
      if (s.includes('sk-ecdsa-sha2-nistp256@openssh.com')) return 'sk-ecdsa-sha2-nistp256@openssh.com';
      if (s.includes('sk-ssh-ed25519@openssh.com')) return 'sk-ssh-ed25519@openssh.com';
      return null;
    };
    let normalizedKeyType = normalizeKeyType(keyType);
    if (!normalizedKeyType && auth.credential_public_key) {
      try {
        const detected = detectKeyTypeFromCOSE(auth.credential_public_key);
        normalizedKeyType = normalizeKeyType(detected) || detected;
      } catch (e) {
        // ignore
      }
    }
    if (!normalizedKeyType) {
      return res.status(400).type('text/plain').send('Error: Unable to determine SSH key type');
    }

    // Determine key type for ssh-keygen (-t flag)
    const sshKeygenType = normalizedKeyType.includes('ed25519') ? 'ed25519-sk' : 'ecdsa-sk';
    const keyFileName = normalizedKeyType.includes('ed25519') ? 'id_ed25519_sk' : 'id_ecdsa_sk';
    
    // Get RP ID for application string
    const rpId = process.env.FIDO2_RP_ID || 'localhost';
    const application = `ssh:${rpId}`;
    
    // Get upload URL for public key
    let uploadUrl;
    if (process.env.BACKEND_PUBLIC_URL) {
      const base = process.env.BACKEND_PUBLIC_URL.replace(/\/$/, '');
      uploadUrl = `${base}/api/webauthn/ssh/upload-pubkey`;
    } else if (process.env.FIDO2_RP_ID && process.env.SERVER_DEFAULT_PORT) {
      const host = process.env.FIDO2_RP_ID;
      const port = process.env.SERVER_DEFAULT_PORT;
      uploadUrl = `http://${host}:${port}/api/webauthn/ssh/upload-pubkey`;
    } else {
      let host = req.get('x-forwarded-host') || req.get('host') || 'localhost';
      host = host.split(':')[0];
      const port = process.env.SERVER_DEFAULT_PORT || '3000';
      uploadUrl = `http://${host}:${port}/api/webauthn/ssh/upload-pubkey`;
    }

    // Generate the install script that creates a resident key with ssh-keygen
    const installScript = `#!/usr/bin/env bash
set -euo pipefail

# Configuration
KEY_TYPE="${sshKeygenType}"
KEY_FILE="\${HOME}/.ssh/${keyFileName}"
APPLICATION="${application}"
UPLOAD_URL="${uploadUrl}"
TOKEN="${token}"

echo "Generating SSH FIDO2 resident key..."
echo "   Type: \${KEY_TYPE}"
echo "   Application: \${APPLICATION}"
echo ""
echo "You will be prompted for your security key PIN"
echo "   Please enter it when prompted"
echo ""

# Create .ssh directory if it doesn't exist
mkdir -p "\${HOME}/.ssh"
chmod 700 "\${HOME}/.ssh"

# Configure SSH client to avoid agent conflicts using ~/.ssh/config
configure_ssh_client() {
  local ssh_config="\${HOME}/.ssh/config"
  local backup_config="\${ssh_config}.bak.\$(date +%s)"

  echo "Checking SSH client configuration in \${ssh_config}"

  # If config file does not exist, create it with Host * / IdentityAgent none
  if [[ ! -f "\${ssh_config}" ]]; then
    echo "SSH config file not found. Creating a new one with Host * / IdentityAgent none."
    {
      echo "Host *"
      echo "  IdentityAgent none"
    } > "\${ssh_config}"
    chmod 600 "\${ssh_config}"
    echo "SSH config created at \${ssh_config}"
    return 0
  fi

  # Detect potential conflicts: any IdentityAgent directive or Host * section
  local has_identity_agent=0
  local has_host_wildcard=0

  if grep -qE '^[[:space:]]*IdentityAgent[[:space:]]+' "\${ssh_config}"; then
    has_identity_agent=1
  fi

  if grep -qE '^[[:space:]]*Host[[:space:]]+\*([[:space:]]|$)' "\${ssh_config}"; then
    has_host_wildcard=1
  fi

  if [[ \${has_identity_agent} -eq 1 || \${has_host_wildcard} -eq 1 ]]; then
    echo "Existing SSH configuration may conflict with setting 'IdentityAgent none' for Host *."
    echo "Current occurrences of IdentityAgent and Host * (if any):"
    grep -nE '^[[:space:]]*(IdentityAgent[[:space:]]+|Host[[:space:]]+\*)' "\${ssh_config}" || true
    echo ""
    printf "Do you want to append a 'Host *' block with 'IdentityAgent none' at the end of \${ssh_config}? [y/N] "
    read -r reply
    case "\${reply}" in
      y|Y|yes|YES)
        ;;
      *)
        echo "User declined to modify SSH config. Skipping SSH client configuration changes."
        return 0
        ;;
    esac
  fi

  echo "Creating backup of existing SSH config at \${backup_config}"
  cp "\${ssh_config}" "\${backup_config}"

  echo "Appending Host * / IdentityAgent none block to \${ssh_config}"
  {
    echo ""
    echo "# Added by ldap-fido-server FIDO2 SSH installer"
    echo "Host *"
    echo "  IdentityAgent none"
  } >> "\${ssh_config}"

  echo "SSH client configuration updated. New connections will ignore ssh-agent for all hosts."
}

configure_ssh_client

# Generate resident key with ssh-keygen
# -t: key type (ecdsa-sk or ed25519-sk)
# -O resident: create a resident key (stored on security token)
# -O application: set application string to "ssh:rpid"
# -O verify-required: require user verification (PIN/biometric)
# -f: output file path
# -N "": no passphrase (key is on hardware token)
# Redirect stdin from /dev/tty to allow PIN input even when piped from curl
if ! ssh-keygen -t "\${KEY_TYPE}" -O resident -O "application=\${APPLICATION}" -O verify-required -f "\${KEY_FILE}" -N "" -C "${auth.username}@${rpId}" < /dev/tty; then
  echo ""
  echo "Failed to generate resident key"
  echo ""
  echo "Common issues:"
  echo "  • Security key not plugged in"
  echo "  • Incorrect PIN (check your security key)"
  echo "  • libfido2 not installed"
  echo "  • Security key doesn't support resident keys"
  echo ""
  exit 1
fi

echo ""
echo "Resident key generated: \${KEY_FILE}"
echo ""

# Upload public key to LDAP
echo "Uploading public key to LDAP..."
PUB_KEY=\$(cat "\${KEY_FILE}.pub")

if ! curl -fsSL -X POST "\${UPLOAD_URL}" \\
  -H "Content-Type: application/json" \\
  -d "{\\"token\\":\\"\${TOKEN}\\",\\"publicKey\\":\\"\${PUB_KEY}\\"}"; then
  echo "Failed to upload public key to LDAP"
  echo "   You may need to upload it manually"
  exit 1
fi

echo ""
echo "SSH FIDO2 setup complete!"
echo "   Private key (stub): \${KEY_FILE}"
echo "   Public key: \${KEY_FILE}.pub"
echo "   Public key uploaded to LDAP"
echo ""
echo "Usage: ssh -i \${KEY_FILE} user@host"
echo ""
echo "Note: The private key is a stub file. The actual key is stored on your security token."
echo "      SSH client has been configured (via IdentityAgent none) to avoid ssh-agent conflicts."
echo "      You can extract the key on any computer with: ssh-keygen -K"
`;

    // Return as plain text script
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.status(200).send(installScript);
  } catch (error) {
    console.error('Error serving install script:', error);
    return res.status(500).type('text/plain').send('Error: Failed to generate install script');
  }
});

/**
 * @route POST /api/webauthn/ssh/upload-pubkey
 * @desc Upload SSH public key to LDAP (single-use, token-based, no auth required)
 * @access Public (token-based)
 */
router.post('/ssh/upload-pubkey', async (req, res, next) => {
  try {
    const { token, publicKey } = req.body;

    // Request debug
    try {
      console.log('[SSH UPLOAD] Incoming request', {
        ip: req.ip,
        ua: req.get('user-agent'),
        origin: req.get('origin') || 'none',
        hasBody: !!req.body,
      });
    } catch {}

    if (!token || typeof token !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid token', code: 'INVALID_TOKEN' });
    }

    if (!publicKey || typeof publicKey !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid public key', code: 'INVALID_PUBLIC_KEY' });
    }

    // Validate public key format (should start with sk-ecdsa-sha2-nistp256@openssh.com or sk-ssh-ed25519@openssh.com)
    if (!publicKey.startsWith('sk-ecdsa-sha2-nistp256@openssh.com ') && 
        !publicKey.startsWith('sk-ssh-ed25519@openssh.com ')) {
      return res.status(400).json({ 
        error: 'Invalid public key format. Must be an OpenSSH FIDO2 key (sk-ecdsa or sk-ed25519)', 
        code: 'INVALID_KEY_FORMAT' 
      });
    }

    // Parse and log public key metadata safely
    try {
      const parts = publicKey.split(/\s+/);
      const pkType = parts[0] || 'unknown';
      const b64 = parts[1] || '';
      const comment = parts.slice(2).join(' ') || '';
      let blobSha256 = 'n/a';
      try {
        const blob = Buffer.from(b64, 'base64');
        blobSha256 = crypto.createHash('sha256').update(blob).digest('base64');
      } catch {}
      console.log('[SSH UPLOAD] Public key meta', {
        type: pkType,
        b64Len: b64.length,
        comment: comment.slice(0, 200),
        blobSha256,
      });
    } catch {}

    // Hash the token to look it up
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    // Look up token
    const tokenResult = await pool.query(
      `SELECT id, user_id, credential_id, expires_at, used_at
       FROM stub_tokens
       WHERE token_hash = $1`,
      [tokenHash]
    );

    if (tokenResult.rows.length === 0) {
      console.warn('[SSH UPLOAD] Token not found');
      return res.status(401).json({ error: 'Invalid token', code: 'INVALID_TOKEN' });
    }

    const tokenRecord = tokenResult.rows[0];
    try {
      console.log('[SSH UPLOAD] Token record', {
        user_id: tokenRecord.user_id,
        credential_id: tokenRecord.credential_id,
        expires_at: tokenRecord.expires_at,
        used_at: tokenRecord.used_at,
      });
    } catch {}

    // Check if already used (allow reuse for upload endpoint since install script uses same token)
    // But check if it was used more than 5 minutes ago
    if (tokenRecord.used_at) {
      const usedAt = new Date(tokenRecord.used_at);
      const now = new Date();
      const minutesSinceUse = (now - usedAt) / 1000 / 60;
      if (minutesSinceUse > 5) {
        console.warn('[SSH UPLOAD] Token previously used and now expired by grace window');
        return res.status(410).json({ error: 'Token expired after use', code: 'TOKEN_EXPIRED' });
      }
    }

    // Check if expired
    if (new Date(tokenRecord.expires_at) < new Date()) {
      console.warn('[SSH UPLOAD] Token expired');
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }

    // Get user info
    const userResult = await pool.query(
      `SELECT id, username FROM users WHERE id = $1`,
      [tokenRecord.user_id]
    );

    if (userResult.rows.length === 0) {
      console.error('[SSH UPLOAD] User not found for token user_id');
      return res.status(404).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
    }

    const user = userResult.rows[0];
    console.log('[SSH UPLOAD] Resolved username for upload:', user.username);

    // Upload public key to LDAP
    try {
      // Import LDAP functions
      const { addSSHPublicKeyToLDAP } = await import('../services/ldapSSHKeyService.js');
      
      console.log('[SSH UPLOAD] Uploading to LDAP...');
      const result = await addSSHPublicKeyToLDAP({ 
        username: user.username, 
        opensshPublicKey: publicKey 
      });
      console.log('[SSH UPLOAD] LDAP upload successful', {
        username: user.username,
        result: !!result,
      });

      return res.json({ 
        success: true, 
        message: 'SSH public key uploaded to LDAP successfully',
        username: user.username
      });
    } catch (ldapError) {
      console.error('[SSH UPLOAD] LDAP upload error:', {
        message: ldapError?.message,
        code: ldapError?.code,
        stack: ldapError?.stack?.split('\n').slice(0, 3).join(' | ')
      });
      return res.status(500).json({ 
        error: 'Failed to upload public key to LDAP', 
        code: 'LDAP_UPLOAD_ERROR',
        details: ldapError.message 
      });
    }
  } catch (error) {
    console.error('Error uploading SSH public key:', {
      message: error?.message,
      stack: error?.stack?.split('\n').slice(0, 3).join(' | ')
    });
    return res.status(500).json({ error: 'Failed to upload public key', code: 'UPLOAD_ERROR' });
  }
});

export default router;
