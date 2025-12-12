import React, { useState, useEffect, useCallback } from 'react';
import { startRegistration } from '@simplewebauthn/browser';
import { useAuth } from '../contexts/AuthContext';
import {
  Box,
  Button,
  Card,
  CardContent,
  TextField,
  Typography,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  LinearProgress
} from '@mui/material';
import { logger } from '../utils/logger';

const Security = ({ user: userProp }) => {
  const { user: authUser, isAuthenticated } = useAuth();
  // Use authUser from context if available, otherwise fall back to prop
  const user = authUser ?? userProp;
  const [authenticator, setAuthenticator] = useState(null);
  const [registering, setRegistering] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [registerToken, setRegisterToken] = useState('');
  const [showTotpDialog, setShowTotpDialog] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [nameDialogOpen, setNameDialogOpen] = useState(false);
  const [nameInputValue, setNameInputValue] = useState(
    user?.displayName ? `${user.displayName}'s Security Key` : "User's Security Key"
  );
  const [pendingCredential, setPendingCredential] = useState(null);
  const [uvDialogOpen, setUvDialogOpen] = useState(false);
  const [uvMessage, setUvMessage] = useState('');
  const [verifiedCredentialId, setVerifiedCredentialId] = useState(null);
  const [downloadingStub, setDownloadingStub] = useState(false);
  const [installCommandDialogOpen, setInstallCommandDialogOpen] = useState(false);
  const [installCommand, setInstallCommand] = useState('');
  const [commandCopied, setCommandCopied] = useState(false);

  /**
   * Converts various input types to a base64url string
   * @param {Buffer|Uint8Array|ArrayBuffer|string} input - The input to convert
   * @returns {string} Base64url encoded string
   */
  const bufferToBase64Url = (input) => {
    if (!input) return '';

    // Handle Node.js-style Buffer object from server
    if (input.type === 'Buffer' && Array.isArray(input.data)) {
      input = new Uint8Array(input.data);
    }

    // Handle Uint8Array
    if (input instanceof Uint8Array) {
      const binary = String.fromCharCode(...input);
      return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    }

    // Handle ArrayBuffer
    if (input instanceof ArrayBuffer) {
      return bufferToBase64Url(new Uint8Array(input));
    }

    // Handle string input (assume it's already in base64url format or needs conversion)
    if (typeof input === 'string') {
      // If it looks like base64 (contains + or /) but not base64url, convert it
      if ((input.includes('+') || input.includes('/')) && !input.includes('-') && !input.includes('_')) {
        return input
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
      }
      return input;
    }

    console.warn('Unsupported format for base64url conversion:', input);
    return '';
  };

  

  // Generate install command for SSH stub
  const generateInstallCommand = async () => {
    if (!authenticator?.credentialId) {
      setError('No credential available');
      return;
    }
    try {
      setDownloadingStub(true);
      setError('');
      setCommandCopied(false);

      // Request single-use token
      const tokenRes = await fetch('/api/webauthn/ssh/stub-token', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credentialId: authenticator.credentialId })
      });

      if (!tokenRes.ok) {
        const errData = await tokenRes.json().catch(() => ({}));
        throw new Error(errData.error ?? 'Failed to generate download token');
      }

      const tokenData = await tokenRes.json();
      const command = `curl -fsSL '${tokenData.downloadUrl}' | bash`;
      
      setInstallCommand(command);
      setInstallCommandDialogOpen(true);
    } catch (err) {
      console.error('Error generating install command:', err);
      setError(err.message ?? 'Failed to generate install command');
    } finally {
      setDownloadingStub(false);
    }
  };

  // Copy install command to clipboard
  const copyInstallCommand = async () => {
    try {
      await navigator.clipboard.writeText(installCommand);
      setCommandCopied(true);
      setTimeout(() => setCommandCopied(false), 3000);
    } catch (err) {
      console.error('Failed to copy:', err);
      setError('Failed to copy to clipboard');
    }
  };

  // Download SSH key stub ZIP for current authenticator
  const downloadSSHStub = async () => {
    if (!authenticator?.credentialId) {
      setError('No credential available for stub download');
      return;
    }
    try {
      setDownloadingStub(true);
      setError('');
      const resp = await fetch(`/api/webauthn/ssh/stub/${encodeURIComponent(authenticator.credentialId)}`, {
        method: 'GET',
        credentials: 'include'
      });
      if (!resp.ok) {
        const contentType = resp.headers.get('content-type') ?? '';
        if (contentType.includes('application/json')) {
          const err = await resp.json();
          throw new Error(err.error ?? 'Failed to download SSH stub');
        }
        const text = await resp.text();
        throw new Error((typeof text === 'string' && text.length) ? text : 'Failed to download SSH stub');
      }
      const blob = await resp.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const cd = resp.headers.get('Content-Disposition') ?? '';
      const match = cd.match(/filename="?([^";]+)"?/i);
      a.download = match ? match[1] : 'ssh-stub.zip';
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setSuccess('SSH key stub downloaded');
      setTimeout(() => setSuccess(''), 3000);
    } catch (e) {
      setError(e.message ?? 'Failed to download SSH stub');
    } finally {
      setDownloadingStub(false);
    }
  };

  /**
   * Converts a base64url string to an ArrayBuffer
   * @param {string} input - Base64url encoded string
   * @returns {ArrayBuffer} Decoded binary data
   */
  const base64UrlToArrayBuffer = (input) => {
    if (!input) throw new Error('Empty input provided to base64UrlToArrayBuffer');
    
    // If already an ArrayBuffer, return as is
    if (input instanceof ArrayBuffer) return input;
    
    // If already a Uint8Array, return its buffer
    if (input instanceof Uint8Array) return input.buffer;

    const base64url = String(input);
    
    // Convert base64url to base64
    let base64 = base64url
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    
    // Add padding if needed
    const pad = base64.length % 4;
    if (pad) {
      if (pad === 1) throw new Error('Invalid base64url string: incorrect padding');
      base64 += '==='.slice(0, 4 - pad);
    }
    
    // Convert to binary string
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    
    return bytes.buffer;
  };

  // Fetch the user's authenticator
  const fetchAuthenticator = useCallback(async () => {
    // Don't proceed if not authenticated
    if (!isAuthenticated) {
      setAuthenticator(null);
      setError('Not authenticated');
      return;
    }

    // Note: user ID may be a temporary placeholder; server will resolve via username
    const sessionUserId = user?.user_id ?? user?.id ?? null;
    if (!sessionUserId || typeof sessionUserId !== 'string') {
      console.warn('Session user ID missing or not a string:', sessionUserId);
    }

    setError('');
    setStatus('Loading security key information...');
    
    try {
      // Get the CSRF token from the meta tag
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
      
      const response = await fetch('/api/webauthn/credentials', {
        method: 'GET',
        credentials: 'include',  // This sends cookies with the request
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          ...(csrfToken && { 'X-CSRF-Token': csrfToken })  // Include CSRF token if available
        },
        mode: 'cors'  // Ensure CORS mode is enabled
      });

      const contentType = response.headers.get('content-type');
      
      if (!response.ok) {
        // Handle 401 Unauthorized specifically
        if (response.status === 401) {
          setError('Your session has expired. Please log in again.');
          setAuthenticator(null);
          return;
        }
        
        // If response is JSON, try to parse the error
        if (contentType && contentType.includes('application/json')) {
          const error = await response.json();
          if (error.code === 'NO_AUTHENTICATOR') {
            // No authenticator found is a valid state
            return;
          }
          if (error.code === 'INVALID_USER_ID') {
            // Bubble up a clearer message and stop re-fetching
            setAuthenticator(null);
            setError('Invalid user ID format in session. Please sign out and sign in again.');
            return;
          }
          throw new Error(error.error ?? 'Failed to fetch authenticator');
        } else {
          // Handle non-JSON error response
          const errorText = await response.text();
          console.error('Non-JSON error response:', errorText);
          throw new Error('Failed to fetch authenticator: Invalid server response');
        }
      }

      // Verify content type before parsing as JSON
      if (!contentType || !contentType.includes('application/json')) {
        const errorText = await response.text();
        console.error('Expected JSON but got:', contentType, errorText);
        throw new Error('Invalid server response format');
      }

      const data = await response.json();

      if (data.authenticator) {
        // Ensure we have all required fields with defaults
        setAuthenticator({
          id: data.authenticator.id,
          name: data.authenticator.name ?? 'Security Key',
          createdAt: data.authenticator.createdAt,
          lastUsed: data.authenticator.lastUsed,
          credentialId: data.authenticator.credential_id
        });
      } else {
        setAuthenticator(null);
      }
    } catch (err) {
      console.error('Failed to fetch authenticator:', err);
      // Don't show error if no authenticator exists (404)
      if (err.message !== 'No authenticator found') {
        setError(err.message ?? 'Failed to load security key information');
      }
      setAuthenticator(null);
    }
  }, [isAuthenticated]);

  // Validate required fields before starting WebAuthn registration
  const validateRegistrationFields = () => {
    if (!registerToken) {
      throw new Error('Registration token is required');
    }
    if (totpCode.length < 6) {
      throw new Error('Please enter a valid TOTP code');
    }
  };

  // Show error message to user
  const showError = (message) => {
    console.error(message);
    setError(message);
    setRegistering(false);
  };

  // Fetch WebAuthn options and handle registration
  const fetchWebAuthnOptions = async (name = '') => {
    try {
      setRegistering(true);
      setError(null);

      // Validate inputs
      validateRegistrationFields();

      const response = await fetch('/api/webauthn/verify-totp', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token: registerToken,
          code: totpCode,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error ?? 'Verification failed');
      }

      const data = await response.json();
      logger.debug('Server response:', data);

      // Parse and validate the server response
      if (!data) {
        throw new Error('No data received from server');
      }

      // Parse the options from optionsJSON string if it exists
      const options = data.optionsJSON ? JSON.parse(data.optionsJSON) : data;
      
      // Log the raw options with sensitive data redacted
      logger.debug('Raw WebAuthn options:', {
        ...options,
        challenge: options.challenge ? '[...]' : 'MISSING',
        user: options.user ? {
          ...options.user,
          id: options.user.id ? '[...]' : 'MISSING'
        } : 'MISSING',
        excludeCredentials: options.excludeCredentials ? 
          options.excludeCredentials.map(c => ({
            ...c,
            id: c.id ? '[...]' : 'MISSING'
          })) : 'NONE'
      });

      // Sanitize and validate WebAuthn options
      const webauthnOptions = {
        rp: {
          name: options.rp?.name ?? 'LDAP FIDO Server',
          id: (typeof options.rp?.id === 'string' && options.rp.id.length) ? options.rp.id : window.location.hostname
        },
        user: {
          // Convert user ID to base64url string
          id: bufferToBase64Url(options.user.id),
          name: options.user?.name ?? options.user?.displayName ?? 'User',
          displayName: options.user?.displayName ?? options.user?.name ?? 'User'
        },
        // Convert challenge to base64url string
        challenge: bufferToBase64Url(options.challenge),
        pubKeyCredParams: (options.pubKeyCredParams ?? [
          { type: 'public-key', alg: -7 },  // ES256
          { type: 'public-key', alg: -257 } // RS256
        ]).map(p => ({
          type: 'public-key',
          alg: p.alg
        })),
        timeout: options.timeout ?? 60000,
        excludeCredentials: (options.excludeCredentials ?? []).map(cred => ({
          id: bufferToBase64Url(cred.id),
          type: 'public-key',
          transports: cred.transports ?? []
        })),
        authenticatorSelection: {
          ...(options.authenticatorSelection ?? {}),
          authenticatorAttachment: options.authenticatorSelection?.authenticatorAttachment ?? 'cross-platform',
          requireResidentKey: options.authenticatorSelection?.requireResidentKey ?? false,
          userVerification: options.authenticatorSelection?.userVerification ?? 'preferred'
        },
        attestation: options.attestation ?? 'none',
        extensions: options.extensions ?? {}
      };
      
        // Start the WebAuthn registration
        setStatus('Waiting for security key interaction...');

        // Log the prepared WebAuthn options (with sensitive data redacted)
        logger.debug('Starting WebAuthn registration with options:', {
          ...webauthnOptions,
          challenge: '[...base64url...]',
          user: {
            ...webauthnOptions.user,
            id: '[...base64url...]'
          },
          excludeCredentials: webauthnOptions.excludeCredentials.map(c => ({
            ...c,
            id: '[...base64url...]'
          }))
        });

        // Log the types of important fields for debugging
        logger.debug('Field types:', {
          challenge: {
            type: typeof webauthnOptions.challenge,
            isString: typeof webauthnOptions.challenge === 'string',
            value: '[...]'
          },
          userId: {
            type: typeof webauthnOptions.user?.id,
            isString: typeof webauthnOptions.user?.id === 'string',
            value: '[...]'
          }
        });
        
        // Call the WebAuthn API to start the registration (v11 signature)
        logger.debug('Starting WebAuthn registration...');
        let credential;
        try {
          credential = await startRegistration({ optionsJSON: webauthnOptions });
          logger.debug('WebAuthn registration successful, credential received');
        } catch (error) {
          console.error('WebAuthn registration failed:', {
            name: error.name,
            message: error.message,
            stack: error.stack,
            options: {
              ...webauthnOptions,
              challenge: '[REDACTED]',
              user: { ...webauthnOptions.user, id: '[REDACTED]' },
              excludeCredentials: webauthnOptions.excludeCredentials.map(c => ({
                ...c,
                id: c.id ? '[REDACTED]' : 'empty'
              }))
            }
          });
          throw error; // Re-throw to be caught by the outer try-catch
        }
        
        if (!credential) {
          const error = new Error('No credential received from authenticator');
          console.error('No credential received:', { webauthnOptions: '...redacted...' });
          throw error;
        }
        
        logger.debug('Received credential from authenticator:', {
          id: credential.id ? `${credential.id.substring(0, 10)}...` : 'missing',
          type: credential.type,
          hasRawId: !!credential.rawId,
          response: {
            hasClientDataJSON: !!credential.response?.clientDataJSON,
            hasAttestationObject: !!credential.response?.attestationObject,
            hasTransports: !!credential.response?.getTransports
          }
        });
        
        logger.debug('Received credential from authenticator');
        setStatus('Processing security key response...');
        
        // Convert the credential to the format expected by the server
        const serializableCredential = {
          // The credential ID is already in base64url format
          id: credential.id,
          // Convert rawId to base64url string
          rawId: bufferToBase64Url(credential.rawId),
          type: credential.type,
          response: {
            // Convert binary data to base64url strings
            attestationObject: bufferToBase64Url(credential.response.attestationObject),
            clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
            transports: credential.response.getTransports ? credential.response.getTransports() : []
          },
          // Include any client extension results
          clientExtensionResults: credential.getClientExtensionResults ? 
            credential.getClientExtensionResults() : {}
        };
        
        // Log the credential structure (with sensitive data redacted)
        logger.debug('Processed credential for server:', {
          id: serializableCredential.id ? `${serializableCredential.id.substring(0, 10)}...` : 'missing',
          type: serializableCredential.type,
          response: {
            hasAttestationObject: !!serializableCredential.response.attestationObject,
            hasClientDataJSON: !!serializableCredential.response.clientDataJSON,
            transports: serializableCredential.response.transports
          }
        });

        // Log the credential structure for debugging
        logger.debug('Processed WebAuthn credential:', {
          id: serializableCredential.id ? `${serializableCredential.id.substring(0, 10)}...` : 'missing',
          type: serializableCredential.type,
          response: {
            hasAttestationObject: !!serializableCredential.response.attestationObject,
            hasClientDataJSON: !!serializableCredential.response.clientDataJSON,
            transports: serializableCredential.response.transports
          }
        });

        // Immediately verify registration with the server; only show naming dialog on success
        try {
          const verifyResponse = await fetch('/api/webauthn/register/verify', {
            method: 'POST',
            credentials: 'include',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
              credential: serializableCredential,
              token: registerToken
            })
          });

          if (!verifyResponse.ok) {
            const errData = await verifyResponse.json();
            if (errData?.code === 'UV_REQUIRED') {
              setUvMessage(errData?.error ?? 'User verification is required. Please use your security key PIN or biometrics and try again.');
              setUvDialogOpen(true);
              setStatus('');
              setRegistering(false);
              return;
            }
            throw new Error(errData?.error ?? errData?.message ?? 'Verification failed');
          }

          const verifyData = await verifyResponse.json();
          const credId = verifyData?.authenticator?.credential_id ?? serializableCredential?.rawId;
          if (!credId) {
            throw new Error('Failed to get credential ID after verification');
          }

          // Store verified credential id and open naming dialog
          setVerifiedCredentialId(credId);
          setPendingCredential(serializableCredential);
          const detectedName = verifyData?.authenticator?.name ?? verifyData?.name;
          if (detectedName) setNameInputValue(detectedName);
          setNameDialogOpen(true);
          setStatus('');
          setRegistering(false);
        } catch (verifyErr) {
          console.error('Registration verification failed:', verifyErr);
          setError(verifyErr.message ?? 'Registration verification failed');
          setStatus('');
          setRegistering(false);
        }
        return;

      // The registration and verification are already handled in the try-catch block
      // No need for additional code here as the flow is complete
      
    } catch (err) {
      console.error('Registration error:', err);
      setError(err.message ?? 'Failed to register security key');
    } finally {
      setRegistering(false);
      setRegisterToken('');
      setShowTotpDialog(false);
      setTotpCode('');
  }
  };

  // Verify TOTP and get WebAuthn options
  const verifyTotpAndGetOptions = async () => {
    try {
      setVerifying(true);
      setError(null);
      setStatus('Verifying TOTP code...');
      await fetchWebAuthnOptions();
    } catch (err) {
      setStatus('');
      console.error('Error in verifyTotpAndGetOptions:', err);
      setError(err.message ?? 'Failed to verify TOTP');
    } finally {
      setVerifying(false);
    }
  };

  // Start the registration process
  const initiateRegistration = async () => {
    try {
      setStatus('Preparing registration...');
      setError(null);
      setSuccess('');
      setVerifying(true);
      setError('');
      const response = await fetch('/api/webauthn/register/init', {
        method: 'POST',
        credentials: 'include'
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message);
      setRegisterToken(data.token);
      setShowTotpDialog(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setVerifying(false);
    }
  };

  // Delete an authenticator
  const deleteAuthenticator = async (id) => {
    if (!window.confirm('Are you sure you want to remove this security key?')) {
      return;
    }
    try {
      const response = await fetch('/api/webauthn/authenticator', {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error ?? 'Failed to delete security key');
      }
      
      setAuthenticator(null);
      setSuccess('Security key removed successfully!');
      // Clear success message after 3 seconds
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      console.error('Error deleting authenticator:', err);
      setError(err.message ?? 'Failed to delete security key');
    }
  };

  // Save the security key with the provided name or use the authenticator's default name
  const handleSaveKeyName = async () => {
    if (!verifiedCredentialId) {
      setError('No verified credential found');
      return;
    }

    // Use the provided name, or the device name from the verification response, or fall back to a default
    const finalName = nameInputValue.trim() ||
                      (pendingCredential?.response?.authenticatorAttachment === 'platform' ? 'Platform Authenticator' :
                       'Security Key');

    if (!finalName) {
      setError('Please enter a name for your security key');
      return;
    }

    try {
      // Finalize the registration with the chosen name using the verified credential ID
      const finalizeResponse = await fetch('/api/webauthn/register/finalize', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          name: finalName,
          credentialId: verifiedCredentialId
        })
      });

      if (!finalizeResponse.ok) {
        const error = await finalizeResponse.json();
        throw new Error(error.message ?? 'Failed to finalize registration');
      }

      // Update the UI with the new authenticator
      const finalizeData = await finalizeResponse.json();
      setAuthenticator({
        id: finalizeData.authenticator.id,
        name: finalName,
        createdAt: new Date().toISOString(),
        lastUsed: null,
        credentialId: verifiedCredentialId,
      });
      
      // Reset the form
      setNameInputValue(user?.displayName ? `${user.displayName}'s Security Key` : "User's Security Key");
      setPendingCredential(null);
      setVerifiedCredentialId(null);
      setNameDialogOpen(false);
      setSuccess('Security key registered successfully!');
      
      // Clear success message after 3 seconds
      setTimeout(() => setSuccess(''), 3000);
      
    } catch (err) {
      console.error('Error saving security key:', err);
      setError(err.message ?? 'Failed to save security key');
    }
  };

  // Track if we've checked authentication status
  const [authChecked, setAuthChecked] = useState(false);

  // Load authenticator when component mounts and when auth state changes
  useEffect(() => {
    let isMounted = true;

    const checkAndFetch = async () => {
      try {
        // Only fetch authenticator if user is authenticated
        if (isAuthenticated) {
          await fetchAuthenticator();
        } else if (isMounted) {
          // Clear authenticator state if not authenticated
          setAuthenticator(null);
          setError('Please log in to manage security keys');
        }
      } catch (err) {
        console.error('Error in auth check:', err);
        if (isMounted) {
          setError('Failed to verify authentication status');
        }
      } finally {
        if (isMounted) {
          setAuthChecked(true);
        }
      }
    };

    checkAndFetch();

    return () => {
      isMounted = false;
    };
  }, [isAuthenticated]);

  // Show loading state while checking auth
  if (!authChecked) {
    return (
      <Box sx={{ p: 3 }}>
        <LinearProgress />
      </Box>
    );
  }

  // Add error handling for unauthenticated users
  if (!isAuthenticated) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="warning">
          Please log in to manage your security keys
        </Alert>
      </Box>
    );
  }

  return (
    <Box>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      {status && (
        <Alert severity="info" sx={{ mb: 2 }}>
          {status}
        </Alert>
      )}
      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>Security Key</Typography>
          
          {!authenticator && !registering && (
            <Box>
              <Typography variant="body1" gutterBottom>No security key registered yet.</Typography>
              <Button 
                variant="contained" 
                color="primary" 
                onClick={initiateRegistration}
                disabled={verifying}
              >
                {verifying ? 'Preparing...' : 'Register Security Key'}
              </Button>
            </Box>
          )}

          {authenticator && (
            <Box>
              <Typography variant="body1" gutterBottom>
                <strong>Security Key:</strong> {authenticator.name}
              </Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                <strong>Registered on:</strong> {new Date(authenticator.createdAt).toLocaleString()}
              </Typography>
              {authenticator.lastUsed && (
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  <strong>Last used:</strong> {new Date(authenticator.lastUsed).toLocaleString()}
                </Typography>
              )}
              <Box mt={2}>
                <Button 
                  variant="contained"
                  color="primary"
                  onClick={downloadSSHStub}
                  disabled={downloadingStub || registering}
                  sx={{ mr: 1, mb: 1 }}
                >
                  {downloadingStub ? 'Preparing stub...' : 'Download SSH key stub'}
                </Button>
                <Button 
                  variant="contained"
                  color="secondary"
                  onClick={generateInstallCommand}
                  disabled={downloadingStub || registering}
                  sx={{ mr: 1, mb: 1 }}
                >
                  {downloadingStub ? 'Generating...' : 'Create SSH Passkey'}
                </Button>
                <Button 
                  variant="outlined" 
                  color="error" 
                  onClick={() => deleteAuthenticator(authenticator.id)}
                  disabled={registering}
                  sx={{ mb: 1 }}
                >
                  {registering ? 'Removing...' : 'Remove Security Key'}
                </Button>
              </Box>
            </Box>
          )}

          {registering && (
            <Box>
              <LinearProgress />
              <Typography variant="body2" style={{ marginTop: 8 }}>
                Completing registration...
              </Typography>
            </Box>
          )}

          
        </CardContent>
      </Card>

      {/* TOTP Verification Dialog */}
      <Dialog open={showTotpDialog} onClose={() => !registering && setShowTotpDialog(false)}>
        <DialogTitle>Verify Your Identity</DialogTitle>
        <DialogContent>
          <Typography variant="body1" gutterBottom>
            Please enter the verification code sent to your email.
          </Typography>
          <TextField
            autoFocus
            margin="dense"
            label="Verification Code"
            type="text"
            fullWidth
            variant="outlined"
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value)}
            disabled={registering}
          />
          {(verifying || registering) && <LinearProgress sx={{ mt: 2 }} />}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowTotpDialog(false)} disabled={registering}>
            Cancel
          </Button>
          <Button
            onClick={verifyTotpAndGetOptions}
            color="primary"
            variant="contained"
            disabled={!totpCode || registering}
          >
            {registering ? 'Registering...' : 'Verify'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Key Name Dialog */}
      <Dialog open={nameDialogOpen} onClose={() => !registering && setNameDialogOpen(false)}>
        <DialogTitle>Name Your Security Key</DialogTitle>
        <DialogContent>
          <Typography variant="body1" gutterBottom>
            Give your security key a name to help you identify it later.
          </Typography>
          <TextField
            autoFocus
            margin="dense"
            label="Security Key Name"
            type="text"
            fullWidth
            variant="outlined"
            value={nameInputValue}
            onChange={(e) => setNameInputValue(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSaveKeyName()}
          />
        </DialogContent>
        <DialogActions>
          <Button 
            onClick={() => {
              setNameDialogOpen(false);
              setError('');
              setPendingCredential(null);
            }} 
            disabled={registering}
          >
            Cancel
          </Button>
          <Button
            onClick={handleSaveKeyName}
            color="primary"
            variant="contained"
            disabled={!nameInputValue.trim() || registering}
          >
            {registering ? 'Saving...' : 'Save'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Install Command Dialog */}
      <Dialog 
        open={installCommandDialogOpen} 
        onClose={() => setInstallCommandDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Create SSH passkey command</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="textSecondary" gutterBottom>
            Copy and paste this command into your terminal to install the SSH stub. This is a single-use command that expires in 10 minutes.
          </Typography>
          <Alert severity="warning" sx={{ mt: 2, mb: 2 }}>
            Only run this command on trusted systems. It will install your SSH key stub to ~/.ssh
          </Alert>
          <Box 
            sx={{ 
              bgcolor: '#f5f5f5', 
              p: 2, 
              borderRadius: 1, 
              fontFamily: 'monospace',
              fontSize: '0.875rem',
              wordBreak: 'break-all',
              overflowX: 'auto'
            }}
          >
            {installCommand}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setInstallCommandDialogOpen(false)}>
            Close
          </Button>
          <Button 
            onClick={copyInstallCommand}
            variant="contained"
            color="primary"
          >
            {commandCopied ? '✓ Copied!' : 'Copy to clipboard'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* UV Required Dialog */}
      <Dialog open={uvDialogOpen} onClose={() => !registering && setUvDialogOpen(false)}>
        <DialogTitle>User verification required</DialogTitle>
        <DialogContent>
          <Typography variant="body1" gutterBottom>
            {uvMessage ?? 'User verification is required. Please use your security key PIN or biometrics and try again.'}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setUvDialogOpen(false);
              setError('');
              // Clear pending credential so the user can restart the WebAuthn registration flow
              setPendingCredential(null);
            }}
            variant="contained"
            color="primary"
          >
            Try again
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Security;