import crypto from 'crypto';
import express from 'express';
import passport from 'passport';
import { Change, Attribute } from 'ldapts';
import cbor from 'cbor';
import base64url from 'base64url';
import { 
  checkLdapUser, 
  ldapClient, 
  changeLdapPassword,
  verifyPassword,
  hashPassword,
  checkPasswordPolicy,
  isUserInAdminGroup
} from '../utils/ldapClient.js';
import { createUserWithRole, getUserByUsername } from '../db/userOps.js';
import { getAuthenticatorByUserId, updateAuthenticatorCounter } from '../db/authenticatorOps.js';
import { 
  storeChallenge, 
  getChallenge, 
  clearChallenge, 
  verifyAndNormalizePublicKey 
} from '../utils/webauthn.js';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { logger } from '../utils/logger.js';

const router = express.Router();

// Nonce endpoint
router.get('/nonce', async (req, res) => {
  try {
    // Prevent caching of this endpoint
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    
    const nonce = crypto.randomBytes(16).toString('hex');
    
    // Debug log
    logger.debug('Generating new nonce - Session ID:', req.sessionID);
    logger.debug('Previous nonce:', req.session.loginNonce);
    
    // Store the nonce in the session
    req.session.loginNonce = nonce;
    
    // Save the session and then send the response
    return new Promise((resolve) => {
      req.session.save(err => {
        if (err) {
          console.error('Error saving session with nonce:', err);
          const response = res.status(500).json({ 
            success: false, 
            message: 'Failed to generate security token' 
          });
          return resolve(response);
        }
        
        logger.debug('New nonce generated and saved to session:', nonce);
        const response = res.json({ nonce });
        return resolve(response);
      });
    });
  } catch (error) {
    console.error('Error in /nonce endpoint:', error);
    res.status(500).json({ success: false, message: 'Failed to generate nonce' });
  }
});

// Decide login method based on username and whether a WebAuthn authenticator exists
router.post('/login-method', async (req, res) => {
  try {
    const { nonce, username, forceAllowCredentials } = req.body ?? {};

    // Validate nonce
    if (!nonce || nonce !== req.session.loginNonce) {
      return res.status(400).json({ success: false, message: 'Invalid or missing nonce' });
    }

    if (!username || typeof username !== 'string') {
      return res.status(400).json({ success: false, message: 'Username is required' });
    }

    // Note: Do NOT delete the nonce here; it will be consumed by the actual login/auth init

    // Protect DB lookups with a timeout to avoid hanging the client
    const DB_TIMEOUT_MS = parseInt(process.env.DB_TIMEOUT_MS ?? '4000', 10);
    const withTimeout = (promise, ms, label) => Promise.race([
      promise,
      new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timed out`)), ms))
    ]);

    // Check if user exists in our DB and if they have an authenticator
    let user = null;
    try {
      user = await withTimeout(getUserByUsername(username), DB_TIMEOUT_MS, 'getUserByUsername');
    } catch (e) {
      console.warn('login-method: user lookup failed or timed out, falling back to password', { username, error: e.message });
      return res.json({ success: true, method: 'password' });
    }

    if (!user) {
      // User may exist in LDAP but not in DB yet -> fall back to password
      return res.json({ success: true, method: 'password' });
    }

    try {
      const authenticator = await withTimeout(getAuthenticatorByUserId(user.id), DB_TIMEOUT_MS, 'getAuthenticatorByUserId');
      if (authenticator) {
        return res.json({ success: true, method: 'webauthn', userId: user.id, username: user.username });
      }
    } catch (e) {
      console.warn('login-method: authenticator lookup failed or timed out, falling back to password', { userId: user.id, error: e.message });
      return res.json({ success: true, method: 'password', userId: user.id, username: user.username });
    }

    return res.json({ success: true, method: 'password', userId: user.id, username: user.username });
  } catch (error) {
    console.error('Error in /login-method:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// WebAuthn login: get options by username (no prior session required)
router.post('/webauthn/options', async (req, res) => {
  try {
    const { nonce, username } = req.body ?? {};
    logger.debug('\n[webauthn/options] Incoming request', {
      sessionID: req.sessionID,
      hasNonce: !!nonce,
      username,
      storedNoncePresent: !!req.session.loginNonce,
      timestamps: {
        received: new Date().toISOString()
      },
      cookie: req.session.cookie
    });
    if (!nonce || nonce !== req.session.loginNonce) {
      console.warn('[webauthn/options] Rejected due to invalid/missing nonce', {
        nonceProvided: !!nonce,
        matchesStoredNonce: nonce === req.session.loginNonce
      });
      return res.status(400).json({ success: false, message: 'Invalid or missing nonce' });
    }
    if (!username) {
      console.warn('[webauthn/options] Missing username');
      return res.status(400).json({ success: false, message: 'Username is required' });
    }

    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const authenticator = await getAuthenticatorByUserId(user.id);
    if (!authenticator) {
      return res.status(404).json({ success: false, message: 'No authenticator registered' });
    }

    // Build authentication options
    const challenge = crypto.randomBytes(32);
    //TODO: Clean this up 
    const userVerificationSetting = (() => {
      const raw = process.env.FIDO2_USER_VERIFICATION?.toLowerCase();
      const allowed = new Set(['required', 'preferred', 'discouraged']);
      return allowed.has(raw) ? raw : 'preferred';
    })();

    // Discoverable (resident key) login mode: omit allowCredentials to let Firefox/CTAP pick resident credential
    const discoverableLogin = (() => {
      const envVal = process.env.FIDO2_DISCOVERABLE_LOGIN;
      if (envVal != null) return String(envVal).toLowerCase() === 'true';
      return true; // default ON since registration requires resident keys
    })();

    // Resolve transports hint for allowCredentials (hardware-only)
    const resolvedTransports = (() => {
      const ALLOWED = new Set(['usb','nfc','ble']);
      const envVal = process.env.FIDO2_ALLOWCREDENTIALS_TRANSPORTS;
      if (envVal) {
        const v = envVal.trim().toLowerCase();
        if (v === 'omit' || v === 'none') return null; // omit transports key entirely
        const parts = v.split(',').map(s => s.trim()).filter(Boolean).filter(t => ALLOWED.has(t));
        if (parts.length) return parts;
      }
      // Default strictly to external hardware transports
      return ['usb','nfc','ble'];
    })();

    const options = {
      rpId: process.env.FIDO2_RP_ID,
      timeout: 60000,
      userVerification: userVerificationSetting,
      // base64url-encoded challenge as required by simplewebauthn JSON format
      challenge: base64url.encode(challenge)
    };

    if (!discoverableLogin) {
      options.allowCredentials = [
        (() => {
          const base = {
            type: 'public-key',
            id: base64url.encode(Buffer.from(authenticator.credential_id, 'hex'))
          };
          if (resolvedTransports) base.transports = resolvedTransports;
          return base;
        })()
      ];
    }

    // Store challenge tied to the user for later verification
    await storeChallenge(user.id, base64url.encode(challenge), 'authentication');

    logger.debug('[webauthn/options] Responding with authentication options', {
      sessionID: req.sessionID,
      userId: user.id,
      rpId: options.rpId,
      allowCredentialsCount: Array.isArray(options.allowCredentials) ? options.allowCredentials.length : 0,
      transports: Array.isArray(options.allowCredentials) ? options.allowCredentials[0]?.transports : undefined,
      userVerification: options.userVerification,
      discoverableLogin,
      challengePreview: options.challenge.substring(0, 12) + '...',
      cookieAfterCall: req.session.cookie
    });

    return res.json({ success: true, options });
  } catch (error) {
    console.error('Error in /webauthn/options:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// WebAuthn login: verify assertion and establish session
router.post('/webauthn/verify', async (req, res, next) => {
  try {
    const { nonce, username, credential } = req.body ?? {};
    logger.debug('\n[webauthn/verify] Incoming request', {
      sessionID: req.sessionID,
      hasNonce: !!nonce,
      hasCredential: !!credential,
      username,
      storedNoncePresent: !!req.session.loginNonce,
      credentialKeys: credential ? Object.keys(credential) : [],
      timestamps: {
        received: new Date().toISOString()
      },
      cookie: req.session.cookie
    });
    if (!nonce || nonce !== req.session.loginNonce) {
      console.warn('[webauthn/verify] Rejected due to invalid/missing nonce', {
        nonceProvided: !!nonce,
        matchesStoredNonce: nonce === req.session.loginNonce
      });
      return res.status(400).json({ success: false, message: 'Invalid or missing nonce' });
    }
    if (!username || !credential) {
      console.warn('[webauthn/verify] Missing username or credential', { hasUsername: !!username, hasCredential: !!credential });
      return res.status(400).json({ success: false, message: 'Username and credential are required' });
    }

    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const authenticator = await getAuthenticatorByUserId(user.id);
    if (!authenticator) return res.status(404).json({ success: false, message: 'No authenticator registered' });

    // Load expected challenge
    const expectedChallenge = await getChallenge(user.id, 'authentication');
    if (!expectedChallenge) {
      return res.status(400).json({ success: false, message: 'No authentication in progress' });
    }

    // Build authenticator object defensively for verification (minimal fields)
    const authForVerification = (() => {
      const credIdHex = authenticator.credential_id;
      // Prefer binary credential_public_key; fall back to legacy public_key
      let pubKey = authenticator.credential_public_key ?? authenticator.public_key;
      const credentialID = credIdHex ? Buffer.from(credIdHex, 'hex') : null;
      let credentialPublicKey = null;
      if (pubKey) {
        if (Buffer.isBuffer(pubKey)) {
          credentialPublicKey = pubKey;
        } else if (typeof pubKey === 'string') {
          const s = pubKey.trim();
          if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) {
            credentialPublicKey = Buffer.from(s, 'hex');
          } else {
            // try base64 then base64url normalization
            try {
              credentialPublicKey = Buffer.from(s, 'base64');
            } catch {
              try {
                let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
                while (b64.length % 4 !== 0) b64 += '=';
                credentialPublicKey = Buffer.from(b64, 'base64');
              } catch (e) {
                console.warn('Failed to parse public key string as hex/base64');
                credentialPublicKey = null;
              }
            }
          }
        } else if (pubKey?.type === 'Buffer' && Array.isArray(pubKey?.data)) {
          credentialPublicKey = Buffer.from(pubKey.data);
        } else if (pubKey instanceof Uint8Array) {
          credentialPublicKey = Buffer.from(pubKey);
        }
      }
      
      // Ensure counter is a valid number, default to 0 if not set
      const counter = (authenticator.counter !== undefined && authenticator.counter !== null)
        ? Number(authenticator.counter)
        : 0;
        
      const transports = Array.isArray(authenticator.transports) 
        ? authenticator.transports 
        : ['internal'];
        
      logger.debug('Authenticator verification data:', {
        hasCredentialID: !!credentialID,
        hasPublicKey: !!credentialPublicKey,
        counter,
        transports
      });
      
      return { 
        credentialID, 
        credentialPublicKey, 
        counter, 
        transports 
      };
    })();

    if (!authForVerification.credentialID || !authForVerification.credentialPublicKey) {
      console.error('Invalid authenticator record for verification', {
        hasCredentialID: !!authForVerification.credentialID,
        hasCredentialPublicKey: !!authForVerification.credentialPublicKey,
      });
      return res.status(400).json({ success: false, message: 'Invalid authenticator data' });
    }

    // Diagnostics: compare incoming vs stored credential IDs and log config
    try {
      const incomingCredIdB64u = credential?.id;
      const expectedCredIdB64u = base64url.encode(Buffer.from(authenticator.credential_id, 'hex'));
      logger.debug('[webauthn/verify] credential id check', {
        incomingCredIdB64u,
        expectedCredIdB64u,
        match: incomingCredIdB64u === expectedCredIdB64u
      });
      logger.debug('[webauthn/verify] expectedOrigin/RPID', {
        expectedOrigin: process.env.FIDO2_RP_ORIGIN,
        expectedRPID: process.env.FIDO2_RP_ID
      });
      logger.debug('[webauthn/verify] credential keys', Object.keys(credential ?? {}));
      logger.debug('[webauthn/verify] credential response diagnostics', {
        hasAuthenticatorData: !!credential?.response?.authenticatorData,
        hasClientDataJSON: !!credential?.response?.clientDataJSON,
        hasSignature: !!credential?.response?.signature,
        hasUserHandle: !!credential?.response?.userHandle,
        clientExtensionKeys: Object.keys(credential?.clientExtensionResults ?? {})
      });
    } catch (e) {
      console.warn('[webauthn/verify] diagnostics logging failed', e?.message);
    }

    // Verify using simplewebauthn
    let verification;
    
    // Get the authenticator data from the database
    const authenticatorFromDB = await getAuthenticatorByUserId(user.id);
    
    // Use already imported modules for COSE key handling
    
    // Log the raw public key for debugging
    logger.debug('Raw public key:', {
      type: typeof authForVerification.credentialPublicKey,
      isBuffer: Buffer.isBuffer(authForVerification.credentialPublicKey),
      value: authForVerification.credentialPublicKey?.toString('base64')?.substring(0, 30) + '...',
      length: authForVerification.credentialPublicKey?.length
    });

    let credentialData;
    try {
      // The public key should already be a Buffer from getAuthenticatorByUserId
      let publicKey = authForVerification.credentialPublicKey;
      
      if (!publicKey || !Buffer.isBuffer(publicKey)) {
        throw new Error('Invalid public key format: Expected Buffer');
      }
      
      // Log the public key in hex for debugging
      logger.debug('Public key hex:', publicKey.toString('hex').substring(0, 60) + '...');
      
      // Verify and normalize the COSE public key
      logger.debug('Verifying and normalizing public key...');
      const normalizedPublicKey = verifyAndNormalizePublicKey(publicKey);
      logger.debug('Public key verified and normalized successfully');

      // Prepare the credential data in the format expected by simplewebauthn
      credentialData = {
        id: authForVerification.credentialID.toString('base64url'),
        // Use the normalized public key
        publicKey: normalizedPublicKey,
        counter: parseInt(authenticatorFromDB.counter ?? '0', 10),
        transports: Array.isArray(authenticatorFromDB.transports) 
          ? authenticatorFromDB.transports 
          : ['internal']
      };
      
      // Log the credential data structure for debugging
      logger.debug('Credential data prepared:', {
        id: credentialData.id ? `${credentialData.id.substring(0, 10)}...` : 'none',
        publicKeyType: credentialData.publicKey ? typeof credentialData.publicKey : 'none',
        publicKeyLength: credentialData.publicKey?.length ?? 0,
        counter: credentialData.counter,
        transports: credentialData.transports
      });
      
      logger.debug('Public key processed:', {
        type: typeof normalizedPublicKey,
        isBuffer: Buffer.isBuffer(normalizedPublicKey),
        length: normalizedPublicKey.length,
        firstBytes: normalizedPublicKey.subarray(0, 8).toString('hex')
      });
      
      logger.debug('Verification input:', {
        hasCredential: !!credential,
        hasExpectedChallenge: !!expectedChallenge,
        expectedOrigin: process.env.FIDO2_RP_ORIGIN,
        expectedRPID: process.env.FIDO2_RP_ID,
        credentialData: {
          hasID: !!credentialData.id,
          hasPublicKey: !!credentialData.publicKey,
          counter: credentialData.counter,
          transports: credentialData.transports
        }
      });

      // Do not verify or return here; proceed to the main verification step below
    } catch (err) {
      console.error('Failed to process public key:', {
        error: err?.message,
        stack: err?.stack,
        publicKeyType: typeof authForVerification.credentialPublicKey,
        isBuffer: Buffer.isBuffer(authForVerification.credentialPublicKey),
        hasCredID: !!authForVerification.credentialID,
        credIdLen: authForVerification.credentialID?.length ?? 0,
        hasPubKey: !!authForVerification.credentialPublicKey
      });
      return res.status(400).json({ 
        success: false, 
        message: 'Failed to process public key', 
        details: err?.message ?? 'Unknown error',
        stack: process.env.NODE_ENV === 'development' ? err?.stack : undefined
      });
    }
    
    try {
      verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge,
        expectedOrigin: process.env.FIDO2_RP_ORIGIN,
        expectedRPID: process.env.FIDO2_RP_ID,
        credential: credentialData,
        requireUserVerification: true
      });
      logger.debug('[webauthn/verify] verifyAuthenticationResponse result', {
        verified: verification?.verified,
        newCounter: verification?.authenticationInfo?.newCounter,
        credentialDeviceType: verification?.authenticationInfo?.credentialDeviceType,
        credentialBackedUp: verification?.authenticationInfo?.credentialBackedUp,
        clientExtensionResults: verification?.authenticationInfo?.clientExtensionResults
      });
    } catch (err) {
      console.error('verifyAuthenticationResponse threw:', {
        error: err?.message,
        stack: err?.stack,
        hasCredID: !!authForVerification.credentialID,
        credIdLen: authForVerification.credentialID?.length ?? 0,
        hasPubKey: !!authForVerification.credentialPublicKey,
        transports: authenticator.transports ?? []
      });
      return res.status(400).json({ success: false, message: 'Verification error', details: err?.message ?? 'Unknown error', stack: err?.stack });
    }

    if (!verification.verified || !verification.authenticationInfo) {
      return res.status(400).json({ 
        success: false, 
        message: 'Authentication verification failed',
        details: verification?.error ?? 'Unknown verification error'
      });
    }

    // Update counter and clear challenge
    await updateAuthenticatorCounter(authenticator.id, verification.authenticationInfo.newCounter ?? 0);
    await clearChallenge(user.id, 'authentication');

    // Invalidate nonce after successful auth
    delete req.session.loginNonce;

    // Log in the user into the session
    const sanitizedUser = { ...user };
    delete sanitizedUser.password;

    req.logIn(sanitizedUser, (loginErr) => {
      if (loginErr) return next(loginErr);
      return res.json({ success: true, user: sanitizedUser });
    });
  } catch (error) {
    console.error('Error in /webauthn/verify:', error);
    return next(error);
  }
});

// Track in-flight login requests to prevent duplicates
const loginInProgress = new Map();

// Login route with nonce/CSRF protection
router.post('/login', async (req, res, next) => {
  const { nonce, username, password } = req.body;
  
  // Debug log the incoming request
  console.log('\n=== NEW LOGIN ATTEMPT ===');
  console.log('Login attempt - Session ID:', req.sessionID);
  console.log('Login attempt - Request body:', { 
    username: username ? `${username.substring(0, 1)}***${username.length > 1 ? username.substring(username.length - 1) : ''}` : 'undefined',
    nonce: nonce ? 'present' : 'missing',
    password: password ? '***' : 'missing' 
  });
  console.log('Login attempt - Session data:', { 
    loginNonce: req.session.loginNonce ? 'present' : 'missing',
    cookie: req.session.cookie 
  });
  
  // Get the stored nonce
  const storedNonce = req.session.loginNonce;
  
  // Validate the nonce first
  if (!nonce) {
    console.error('No nonce provided in request');
    return res.status(400).json({ 
      success: false, 
      message: 'Missing security token. Please refresh the page and try again.'
    });
  }
  
  if (!storedNonce) {
    console.error('No nonce found in session');
    return res.status(400).json({ 
      success: false, 
      message: 'Session expired. Please refresh the page and try again.'
    });
  }
  
  // If a WebAuthn authenticator exists for this user, require WebAuthn instead of password
  try {
    const dbUser = await getUserByUsername(username);
    if (dbUser) {
      const existingAuth = await getAuthenticatorByUserId(dbUser.id);
      if (existingAuth) {
        console.warn(`Password login blocked for user '${username}': WebAuthn authenticator exists`);
        return res.status(400).json({
          success: false,
          code: 'WEBAUTHN_REQUIRED',
          message: 'This account requires Security Key (WebAuthn) login.'
        });
      }
    }
  } catch (precheckErr) {
    console.error('Precheck for WebAuthn requirement failed:', precheckErr);
    // Continue with normal flow if precheck fails
  }

  if (nonce !== storedNonce) {
    console.error('Nonce mismatch');
    console.error('Received nonce:', nonce);
    console.error('Expected nonce:', storedNonce);
    return res.status(400).json({ 
      success: false, 
      message: 'Invalid security token. Please refresh the page and try again.'
    });
  }
  
  // Check for duplicate login requests
  if (loginInProgress.has(username)) {
    const errorMsg = `Login already in progress for user: ${username}`;
    console.warn(errorMsg);
    console.log('Current loginInProgress map:', [...loginInProgress.entries()]);
    return res.status(429).json({
      success: false,
      message: 'Login attempt already in progress. Please wait...'
    });
  }
  
  // Mark login as in progress with a timestamp
  const loginStartTime = Date.now();
  loginInProgress.set(username, loginStartTime);
  console.log(`Marked login in progress for user: ${username} at ${new Date(loginStartTime).toISOString()}`);
  console.log('Current loginInProgress map after set:', [...loginInProgress.entries()]);
  
  // Add a timeout to auto-cleanup if something goes wrong (5 minutes)
  const loginTimeout = setTimeout(() => {
    if (loginInProgress.get(username) === loginStartTime) {
      console.warn(`Auto-cleaning up stale login attempt for user: ${username}`);
      cleanup();
    }
  }, 5 * 60 * 1000); // 5 minutes
  
  // Clean up function to remove from loginInProgress map
  const cleanup = () => {
    if (username && loginInProgress.has(username)) {
      console.log(`Cleaning up login in progress for user: ${username}`);
      loginInProgress.delete(username);
      console.log('loginInProgress map after cleanup:', [...loginInProgress.entries()]);
    } else if (username) {
      // If we have a username but it's not in the map, log it for debugging
      console.log(`No cleanup needed for user: ${username}`);
    } else {
      console.log('No username provided for cleanup');
    }
  };
  
  // Clean up with delay to prevent race conditions
  const cleanupWithDelay = () => {
    // Use a longer delay to ensure the response is sent first
    setTimeout(cleanup, 2000);
  };
  
  // Helper function to clear nonce and save session
  const clearNonceAndSave = async () => {
    if (req.session) {
      try {
        delete req.session.loginNonce;
        await new Promise((resolve, reject) => {
          req.session.save(err => {
            if (err) {
              console.error('Error saving session after clearing nonce:', err);
              return reject(err);
            }
            console.log('Successfully cleared nonce from session');
            resolve();
          });
        });
      } catch (error) {
        console.error('Error in clearNonceAndSave:', error);
        throw error; // Re-throw to be caught by the main try-catch
      }
    }
  };
  
  try {
    // Validate required fields
    if (!username || !password) {
      await clearNonceAndSave();
      cleanup();
      return res.status(400).json({ 
        success: false, 
        message: 'Username and password are required' 
      });
    }
    
    console.log('\n=== STARTING AUTHENTICATION ===');
    console.log('Authenticating user:', username);
    console.log('Session ID:', req.sessionID);
    console.log('Request headers:', {
      'user-agent': req.headers['user-agent'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-real-ip': req.headers['x-real-ip']
    });
    
    // Save the session before starting authentication
    await new Promise((resolve, reject) => {
      req.session.save(err => err ? reject(err) : resolve());
    });
    console.log('Session saved before authentication');
    
    // Authenticate using LDAP strategy
    console.log('Starting LDAP authentication...');
    
    // Use the LDAP strategy for authentication
    passport.authenticate('ldapauth', { 
      session: true, // Enable session support
      failWithError: true // Important: This makes Passport return errors to our callback
    }, async (err, user, info) => {
      // Clean up login in progress
      cleanup();
      clearTimeout(loginTimeout);
      
      try {
        // This is our custom verification callback
        console.log('\n=== AUTH CALLBACK TRIGGERED ===');
        console.log('Auth callback - Error:', err ? err.message : 'none');
        console.log('Auth callback - User:', user ? 'present' : 'missing');
        console.log('Auth callback - Info:', info ?? '{}');
        console.log('Auth callback - Session ID:', req.sessionID);
        console.log('Auth callback - Is authenticated (pre):', req.isAuthenticated ? req.isAuthenticated() : 'req.isAuthenticated not a function');
        console.log('');
        
        if (err) {
          console.error('Auth callback error:', err);
          // Clear the session on error to prevent session fixation
          req.session.destroy(() => {
            console.log('Session destroyed due to auth error');
          });
          
          // Clear the nonce from the session
          await clearNonceAndSave();
          
          return res.status(401).json({ 
            success: false, 
            message: 'Authentication failed',
            error: err.message 
          });
        }
        
        // If no user was authenticated, return an error
        if (!user) {
          console.error('No user returned from authentication');
          // Clear the session on failed authentication
          req.session.destroy(() => {
            console.log('Session destroyed due to failed authentication');
          });
          
          // Clear the nonce from the session
          await clearNonceAndSave();
          
          return res.status(401).json({ 
            success: false, 
            message: info?.message ?? 'Authentication failed',
            info: info
          });
        }
        
        try {
          // Ensure we have a persistent user id for session serialization
          const isAdmin = user.isAdmin ?? false;
          let userId;

          try {
            // Create or update the user with the correct role
            userId = await createUserWithRole({
              username: user.username,
              email: user.email ?? `${user.username}@example.com`,
              roleName: isAdmin ? 'admin' : 'user',
              displayName: user.displayName ?? user.username
            });
            console.log(`[Auth] User ${user.username} synced to database with ID: ${userId}`);
          } catch (dbError) {
            console.error('Error syncing user to database:', dbError);
            // Fallback to temporary id to not break session, but log clearly
            userId = `temp_${Date.now()}`;
          }

          // Build sanitized user for the session (must include id & username)
          const sanitizedUser = {
            id: userId,
            username: user.username,
            displayName: user.displayName ?? user.username,
            email: user.email ?? `${user.username}@example.com`,
            isAdmin: isAdmin,
            roles: Array.isArray(user.roles) ? user.roles : (isAdmin ? ['admin'] : ['user'])
          };

          // Establish the login session with sanitizedUser
          req.logIn(sanitizedUser, async (loginErr) => {
            if (loginErr) {
              console.error('Error in req.logIn:', loginErr);
              // Clear the session on error
              req.session.destroy(() => {
                console.log('Session destroyed due to login error');
              });

              await clearNonceAndSave();

              return res.status(500).json({
                success: false,
                message: 'Error establishing login session',
                error: loginErr.message
              });
            }

            console.log('User authenticated successfully:', sanitizedUser.username, 'ID:', sanitizedUser.id);
            console.log('Is authenticated (post):', req.isAuthenticated ? req.isAuthenticated() : 'req.isAuthenticated not a function');

            try {
              // Save the session to persist the user
              await new Promise((resolveSave, rejectSave) => {
                req.session.save(err => err ? rejectSave(err) : resolveSave());
              });
              console.log('Session saved after login');
            } catch (saveErr) {
              console.error('Error saving session after login:', saveErr);
            }

            // Clear the nonce from the session
            await clearNonceAndSave();

            // Return the user data
            return res.json({
              success: true,
              message: 'Login successful',
              user: sanitizedUser
            });
          });
        } catch (loginError) {
          console.error('Error in login process:', loginError);
          // Clear the session on error
          req.session.destroy(() => {
            console.log('Session destroyed due to login process error');
          });
          
          await clearNonceAndSave();
          
          return res.status(500).json({ 
            success: false, 
            message: 'Error during login process',
            error: loginError.message 
          });
        }
      } catch (error) {
        console.error('Error in authentication callback:', error);
        
        // Only send error response if headers haven't been sent yet
        if (!res.headersSent) {
          const statusCode = error.code === 'INVALID_CREDENTIALS' ? 401 : 500;
          res.status(statusCode).json({
            success: false,
            message: statusCode === 401 ? 'Invalid username or password' : 'An unexpected error occurred during login',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
          });
        }
      }
    })(req, res, next); // Immediately invoke the passport.authenticate middleware
    
  } catch (error) {
    console.error('Error during login process:', {
      message: error.message,
      stack: error.stack,
      code: error.code,
      ldapResultCode: error.ldapResultCode,
      ldapErrorMessage: error.ldapErrorMessage
    });
    
    // Ensure we clean up in all error cases
    cleanup();
    
    try {
      // Try to send error response
      if (!res.headersSent) {
        const statusCode = error.code === 'INVALID_CREDENTIALS' ? 401 : 500;
        res.status(statusCode).json({
          success: false,
          message: statusCode === 401 ? 'Invalid username or password' : 'An unexpected error occurred during login',
          error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
      }
    } catch (responseError) {
      console.error('Failed to send error response:', responseError);
    }
    // Don't call next() here as we've already sent a response
    return;
  }
});

// Logout route
router.post('/logout', (req, res, next) => {
  console.log('Logout request received for user:', req.user?.username ?? 'unknown');
  
  // Clear the session
  req.logout((err) => {
    if (err) {
      console.error('Error during logout:', err);
      return next(err);
    }
    
    // Clear the session cookie
    if (req.session) {
      req.session.destroy((err) => {
        if (err) {
          console.error('Error destroying session:', err);
          return next(err);
        }
        
        // Clear the session cookie
        res.clearCookie('ldap-fido.sid', {
          path: '/',
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax'
        });
        
        console.log('User logged out successfully');
        res.json({ success: true, message: 'Logged out successfully' });
      });
    } else {
      // If there's no session, still send success response
      res.json({ success: true, message: 'Not logged in' });
    }
  });
});

// Authenticated user info
router.get('/me', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: req.user });
});

// Generate a secure password hash using the specified algorithm
// This is kept for backward compatibility but now uses the ldapClient implementation
async function generatePasswordHash(password, algorithm = 'SSHA') {
  return await hashPassword(password, algorithm);
}

// Change password endpoint
router.post('/change-password', async (req, res) => {
  if (!req.isAuthenticated?.() || !req.user) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  
  const { currentPassword, newPassword, hashAlgorithm = 'SSHA' } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ 
      success: false, 
      message: 'Current and new password are required' 
    });
  }

  // Validate new password against LDAP password policy
  try {
    const policyCheck = await checkPasswordPolicy(newPassword);
    if (!policyCheck.valid) {
      return res.status(400).json({
        success: false,
        message: policyCheck.message ?? 'Password does not meet the password policy requirements'
      });
    }
  } catch (error) {
    console.error('Error checking password policy:', error);
    return res.status(500).json({
      success: false,
      message: 'Error validating password against password policy'
    });
  }

  // Validate hash algorithm
  const validAlgorithms = ['SSHA', 'SHA', 'CRYPT'];
  if (!validAlgorithms.includes(hashAlgorithm)) {
    return res.status(400).json({
      success: false,
      message: `Invalid hash algorithm. Must be one of: ${validAlgorithms.join(', ')}`
    });
  }

  const username = req.user.uid || req.user.username;
  
  try {
    console.log(`Attempting to change password for user: ${username}`);
    
    // Use the new changeLdapPassword function from ldapClient
    await changeLdapPassword(username, currentPassword, newPassword, hashAlgorithm);
    
    console.log('Password updated successfully in LDAP');
    return res.json({ 
      success: true,
      message: 'Password changed successfully' 
    });
    
  } catch (error) {
    console.error('Password change failed:', error);
    
    // Handle specific error cases with appropriate messages
    if (error.message.includes('current password is incorrect')) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect.'
      });
    }
    
    if (error.message.includes('password change not allowed')) {
      return res.status(403).json({
        success: false,
        message: 'You do not have permission to change this password.'
      });
    }
    
    // Generic error for other cases
    return res.status(500).json({
      success: false,
      message: 'Failed to update password. Please try again later.'
    });
  }
});

/**
 * Test endpoint to verify LDAP credentials directly
 * This is for debugging purposes only and should be removed in production
 */
// Debug endpoint to inspect LDAP user entry
router.get('/debug/ldap-user/:username', async (req, res) => {
  const { username } = req.params;
  
  if (!username) {
    return res.status(400).json({
      success: false,
      message: 'Username is required'
    });
  }
  
  try {
    await ldapClient.connect();
    
    // Search for the user
    const searchResult = await ldapClient.search(
      process.env.LDAP_SEARCH_BASE_USERS ?? 'ou=users,dc=example,dc=org',
      {
        scope: 'sub',
        filter: `(uid=${username})`,
        attributes: ['*', '+']
      }
    );
    
    if (!searchResult.searchEntries || searchResult.searchEntries.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found in LDAP'
      });
    }
    
    const user = searchResult.searchEntries[0];
    
    // Don't expose password hashes in the response
    const sanitizedUser = { ...user };
    if (sanitizedUser.userPassword) {
      sanitizedUser.passwordHashTypes = Array.isArray(sanitizedUser.userPassword)
        ? sanitizedUser.userPassword.map(p => ({
            type: p.startsWith('{') ? p.match(/^{([^}]+)/)[1] : 'plain',
            length: p.length
          }))
        : [{
            type: 'unknown',
            length: typeof sanitizedUser.userPassword === 'string' 
              ? sanitizedUser.userPassword.length 
              : 'not a string'
          }];
      delete sanitizedUser.userPassword;
    }
    
    res.json({
      success: true,
      user: sanitizedUser
    });
    
  } catch (error) {
    console.error('Error fetching LDAP user:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user from LDAP',
      error: error.message
    });
  } finally {
    try {
      await ldapClient.unbind();
    } catch (e) {
      console.error('Error during LDAP unbind:', e);
    }
  }
});


router.post('/test-ldap', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Username and password are required'
    });
  }
  
  try {
    console.log(`[Test LDAP] Testing credentials for user: ${username}`);
    const user = await checkLdapUser(username, password);
    
    if (user) {
      return res.json({
        success: true,
        message: 'LDAP authentication successful',
        user: {
          dn: user.dn,
          uid: user.uid,
          cn: user.cn,
          mail: user.mail,
          objectClass: user.objectClass,
          hasPassword: !!user.userPassword
        }
      });
    } else {
      return res.status(401).json({
        success: false,
        message: 'LDAP authentication failed'
      });
    }
  } catch (error) {
    console.error('[Test LDAP] Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error testing LDAP credentials',
      error: error.message
    });
  }
});

export default router;
