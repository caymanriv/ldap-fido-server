import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
const DEFAULT_TOTP_LENGTH = process.env.SMTP_TOTP_LENGTH ? parseInt(process.env.SMTP_TOTP_LENGTH, 10) : 6;

// In-memory store for TOTP secrets (in production, consider using Redis with expiration)
const totpSecrets = new Map();

/**
 * Generate a cryptographically secure random numeric code of specified length
 * @param {number} length - Length of the code to generate (max 20 digits)
 * @returns {string} - Numeric code as string
 * @throws {Error} If length is invalid or random bytes generation fails
 */
function generateNumericCode(length = DEFAULT_TOTP_LENGTH) {
  // Validate input
  if (typeof length !== 'number' || length < 1 || length > DEFAULT_TOTP_LENGTH) {
    throw new Error('Code length must be between 1 and ' + DEFAULT_TOTP_LENGTH + ' digits');
  }

  // Calculate the number of bytes needed (2 bytes per digit to ensure uniform distribution)
  const byteCount = Math.ceil(length * 1.6); // 1.6 bytes per digit (10 possibilities per byte)
  
  try {
    // Generate secure random bytes
    const randomBytes = crypto.randomBytes(byteCount);
    let code = '';
    
    while (code.length < length) {
      // Convert each byte to a value between 0-9
      for (const byte of randomBytes) {
        // Only use values 0-9 (0-9 is 0-9 in ASCII)
        if (byte <= 250) {
          // Use modulo 10 to get a digit 0-9
          code += (byte % 10).toString();
          if (code.length >= length) break;
        }
      }
    }
    
    return code.slice(0, length);
  } catch (error) {
    console.error('Failed to generate secure random code:', error);
    throw new Error('Failed to generate secure code');
  }
}

/**
 * Generate a TOTP secret for a user
 * @param {string} userId - User ID
 * @returns {{code: string, token: string}} - Returns the 6-digit code and a one-time token
 */
function generateTotpSecret(userId) {
  // Generate a 6-digit numeric code
  const code = generateNumericCode(6);
  const token = uuidv4();
  
  // Store the code with a 10-minute expiration
  totpSecrets.set(token, {
    userId,
    code,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
    verified: false
  });
  
  console.log(`Generated 6-digit code for user ${userId}: ${code}`);
  
  return { 
    code, // Return the 6-digit code to be sent via email
    token 
  };
}

/**
 * Verify a TOTP code
 * @param {string} token - The token received from generateTotpSecret
 * @param {string} code - The 6-digit code to verify
 * @returns {{valid: boolean, userId: string|null}} - Verification result and user ID if valid
 */
function verifyTotpCode(token, code) {
  console.log(`Verifying 6-digit code for token: ${token}`);
  
  const totpData = totpSecrets.get(token);
  
  // Check if token exists and is not expired
  if (!totpData) {
    console.error('Verification token not found');
    return { valid: false, userId: null };
  }
  
  if (totpData.expiresAt < Date.now()) {
    console.error('Verification code expired:', {
      now: new Date().toISOString(),
      expiresAt: new Date(totpData.expiresAt).toISOString()
    });
    return { valid: false, userId: null };
  }
  
  console.log('Verification data found:', {
    userId: totpData.userId,
    expiresAt: new Date(totpData.expiresAt).toISOString(),
    verified: totpData.verified || false
  });
  
  try {
    // Simple string comparison (case-sensitive)
    const isValid = totpData.code === code;
    
    console.log('Verification result:', { 
      isValid, 
      providedCode: code,
      expectedCode: totpData.code
    });
    
    if (isValid) {
      totpData.verified = true;
      console.log('Verification successful for user ID:', totpData.userId);
      return { valid: true, userId: totpData.userId };
    }
    
    console.error('Verification code does not match');
    return { valid: false, userId: null };
    
  } catch (error) {
    console.error('Error during verification:', error);
    return { valid: false, userId: null };
  }
}

/**
 * Check if a TOTP token is verified
 * @param {string} token - The token to check
 * @returns {boolean} - True if verified, false otherwise
 */
function isTotpVerified(token) {
  const totpData = totpSecrets.get(token);
  return !!(totpData && totpData.verified);
}

/**
 * Clean up expired TOTP data
 */
function cleanupExpiredTotp() {
  const now = Date.now();
  for (const [token, data] of totpSecrets.entries()) {
    if (data.expiresAt < now) {
      totpSecrets.delete(token);
    }
  }
}

// Clean up expired TOTP data every hour
setInterval(cleanupExpiredTotp, 60 * 60 * 1000);

export {
  generateNumericCode,
  generateTotpSecret,
  verifyTotpCode,
  isTotpVerified,
  cleanupExpiredTotp
};
