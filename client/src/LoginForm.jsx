import React, { useState, useEffect, useRef, useCallback } from 'react';
import { startAuthentication } from '@simplewebauthn/browser';
import useNonce from './hooks/useNonce';
import { handleApiError, isNetworkError } from './utils/errorHandler';
import { useAuth } from './contexts/AuthContext';
import { getLoginMethod } from './utils/auth';

// Error message component with back button
const ErrorMessage = ({ error, onBack }) => {
  if (!error) return null;
  
  let displayError = error;
  if (error === 'Invalid username or password') {
    displayError = 'Incorrect username or password. Please try again.';
  } else if (error.includes('Network Error')) {
    displayError = 'Unable to connect to the server. Please check your connection and try again.';
  }
  
  return (
    <div className="alert alert-danger" role="alert">
      <div className="d-flex align-items-center">
        <i className="bi bi-exclamation-triangle-fill me-2"></i>
        <div>{displayError}</div>
      </div>
      <button 
        type="button"
        onClick={onBack}
        className="btn btn-outline-primary mt-3"
      >
        Back to Sign In
      </button>
    </div>
  );
};

// WebAuthn prompt component
const WebAuthnPrompt = ({ onBackToPassword, onStart, isLoading, ready, showBackToPassword = true }) => (
  <div className="text-center">
    <div className="mb-3">
      <p>Please use your security key or biometric to sign in</p>
      {isLoading && (
        <div className="d-flex justify-content-center align-items-center">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
        </div>
      )}
    </div>
    <div className="d-grid gap-2 mb-2">
      <button
        type="button"
        className="btn btn-primary"
        onClick={onStart}
        disabled={isLoading || !ready}
      >
        Continue with Security Key
      </button>
    </div>
    {/* Automatic WebAuthn flow triggers without a button */}
    {showBackToPassword && (
      <button 
        type="button" 
        className="btn btn-outline-secondary btn-sm"
        onClick={onBackToPassword}
        disabled={isLoading}
      >
        Use password instead
      </button>
    )}
  </div>
);

// Password form component
const PasswordForm = React.memo(({ 
  password, 
  setPassword, 
  passwordSubmit, 
  isLoading, 
  error,
  setError,
  passwordRef,
  onBack
}) => {
  const isMounted = useRef(true);
  const [localPassword, setLocalPassword] = useState(password ?? '');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [exposePasswordField, setExposePasswordField] = useState(false);
  
  useEffect(() => {
    return () => {
      isMounted.current = false;
    };
  }, []);
  
  // Update local password when prop changes
  useEffect(() => {
    if (password !== localPassword) {
      setLocalPassword(password ?? '');
    }
  }, [password]);
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!localPassword.trim()) {
      setError('Please enter your password');
      return;
    }
    
    setExposePasswordField(true);
    setIsSubmitting(true);
    setPassword(localPassword);
    
    try {
      await passwordSubmit(localPassword);
    } finally {
      if (isMounted.current) {
        setIsSubmitting(false);
        setExposePasswordField(false);
      }
    }
  };
  
  const handlePasswordChange = (e) => {
    const newPassword = e.target.value;
    setLocalPassword(newPassword);
    if (error) {
      setError('');
    }
  };
  
  return (
    <form onSubmit={handleSubmit} autoComplete="on">
      <div className="mb-3">
        <div className="input-group">
          <input
            type="password"
            className={`form-control ${error ? 'is-invalid' : ''}`}
            id="password"
            placeholder="Password"
            value={localPassword}
            onChange={handlePasswordChange}
            disabled={isLoading || isSubmitting}
            autoComplete="current-password"
            ref={passwordRef}
            aria-describedby="passwordHelp"
          />
          {exposePasswordField && (
            <input
              type="password"
              name="password"
              value={localPassword}
              readOnly
              style={{ display: 'none' }}
              autoComplete="current-password"
            />
          )}
        </div>
        {error && (
          <div className="invalid-feedback d-block">
            {error}
          </div>
        )}
      </div>
      <div className="d-grid gap-2">
				{onBack && (
					<button
						type="button"
						className="btn btn-outline-primary"
						onClick={onBack}
						disabled={isLoading || isSubmitting}
					>
						Back to Sign In
					</button>
				)}
        <button 
          type="submit" 
          className="btn btn-primary"
          disabled={isLoading || isSubmitting || !localPassword.trim()}
        >
          {isLoading || isSubmitting ? (
            <>
              <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
              Signing in...
            </>
          ) : (
            'Sign In'
          )}
        </button>
      </div>
    </form>
  );
});

// Main LoginForm component
function LoginForm() {
  const { login, refreshAuth } = useAuth();
  const [formState, setFormState] = useState({
    username: '',
    password: '',
    error: '',
    isLoading: false,
    step: 'username', // 'username' | 'password' | 'webauthn'
    usernameSubmitted: false,
    userHasWebAuthn: false,
    formKey: 0, // Used to force re-render
    hasLoginError: false, // Track if there was a login error
    allowPasswordFallback: true // Hide password option when WebAuthn required
  });
  
  const passwordRef = useRef(null);
  const webauthnInProgressRef = useRef(false);
  const webauthnAbortRef = useRef(null);
  const webauthnRetriedNonceRef = useRef(false);
  const { nonce, refreshNonce, ensureNonce } = useNonce();
  const [loginNonce, setLoginNonce] = useState('');
  const [webauthnOptions, setWebauthnOptions] = useState(null);
  const [optionsLoading, setOptionsLoading] = useState(false);
  const prefetchStartedRef = useRef(false);
  const prefetchKeyRef = useRef('');
  const isFirefox = typeof navigator !== 'undefined' && /firefox/i.test(navigator.userAgent);
  
  // Helper to update form state
  const updateFormState = useCallback((updates) => {
    setFormState(prev => ({
      ...prev,
      ...updates
    }));
  }, []);
  
  // Reset form to initial state
  const resetForm = useCallback(() => {
    setFormState(prev => ({
      username: '',
      password: '',
      error: '',
      isLoading: false,
      step: 'username',
      usernameSubmitted: false,
      userHasWebAuthn: false,
      formKey: prev.formKey + 1,
      hasLoginError: false
    }));
  }, []);
  
  // Reset to username input while keeping the current username
  const resetToUsernameInput = useCallback(() => {
    setFormState(prev => ({
      ...prev,
      step: 'username',
      password: '',
      error: '',
      isLoading: false,
      hasLoginError: false
    }));
  }, []);
  
  // Handle password submission
  const handlePasswordSubmit = useCallback(async (password) => {
    try {
      updateFormState({ isLoading: true, error: '' });
      
      // Ensure we have a valid nonce bound to the current session
      const validNonce = await ensureNonce();
      // Call the login function from AuthContext
      await login(formState.username, password, validNonce);
      
      // If login is successful, the AuthContext will handle the redirect
      // So we don't need to do anything here
    } catch (err) {
      console.error('Login error:', err);
      if (err.code === 'WEBAUTHN_REQUIRED') {
        // Switch to WebAuthn step if server enforces it
        updateFormState({
          step: 'webauthn',
          isLoading: false,
          error: 'This account requires Security Key (WebAuthn) login.',
          allowPasswordFallback: false
        });
        return;
      }
      
      // Handle network errors separately
      if (isNetworkError(err)) {
        updateFormState({
          error: 'Network error. Please check your connection and try again.',
          isLoading: false,
          hasLoginError: true,
          step: 'username',
          password: ''
        });
        return;
      }
      
      // Handle other errors
      updateFormState({
        error: err.message ?? 'Failed to log in. Please try again.',
        isLoading: false,
        hasLoginError: true,
        step: 'username',
        password: ''
      });
      
      // Get a fresh nonce after an error
      try {
        await refreshNonce();
      } catch (nonceErr) {
        console.error('Failed to refresh nonce:', nonceErr);
      }
    }
  }, [formState.username, login, nonce, refreshNonce, updateFormState]);
  
  // Check if WebAuthn is available
  useEffect(() => {
    const checkWebAuthnSupport = async () => {
      if (window.PublicKeyCredential) {
        try {
          const isAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
          updateFormState({ userHasWebAuthn: isAvailable });
        } catch (err) {
          console.warn('WebAuthn not supported:', err);
          updateFormState({ userHasWebAuthn: false });
        }
      }
    };
    
    checkWebAuthnSupport();
  }, [updateFormState]);
  
  // Focus password field when it becomes visible
  useEffect(() => {
    if (formState.step === 'password' && passwordRef.current) {
      passwordRef.current.focus();
    }
  }, [formState.step]);

  // Prefetch authentication options when entering the webauthn step
  useEffect(() => {
    const prefetch = async () => {
      if (!(formState.usernameSubmitted && formState.step === 'webauthn' && formState.username)) return;
      const key = `${formState.username}|${formState.step}`;
      if (prefetchStartedRef.current && prefetchKeyRef.current === key) return;
      try {
        setOptionsLoading(true);
        prefetchStartedRef.current = true;
        prefetchKeyRef.current = key;
        const validNonce = loginNonce || (await ensureNonce());
        if (!loginNonce) setLoginNonce(validNonce);
        const res = await fetch('/api/auth/webauthn/options', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: formState.username.trim(), nonce: validNonce })
        });
        const data = await res.json().catch(() => null);
        if (res.ok && data?.success) {
          setWebauthnOptions(data.options ?? data);
        } else {
          setWebauthnOptions(null);
        }
      } catch (e) {
        setWebauthnOptions(null);
      } finally {
        setOptionsLoading(false);
      }
    };
    prefetch();
  }, [formState.usernameSubmitted, formState.step, formState.username, loginNonce]);

  // Click-triggered WebAuthn login flow (requires user gesture)
  const runWebAuthnLogin = useCallback(async () => {
    if (formState.step !== 'webauthn' || !formState.usernameSubmitted || !formState.username) return;
    if (webauthnInProgressRef.current) return;
    // Global guard to prevent any overlapping navigator.credentials.get() across the app (Firefox aborts on parallel requests)
    if (typeof window !== 'undefined') {
      if (window.__webauthnPending) {
        return;
      }
      window.__webauthnPending = true;
    }
    try {
      webauthnInProgressRef.current = true;
      // Abort any previous pending WebAuthn request defensively
      if (webauthnAbortRef.current) {
        try { webauthnAbortRef.current.abort(); } catch {}
      }
      webauthnAbortRef.current = new AbortController();

      // Use prefetched options to keep the user gesture context intact
      let publicKeyOptions = webauthnOptions;
      if (!publicKeyOptions) {
        updateFormState({ isLoading: false, error: 'Security key is not ready yet. Please try again.', usernameSubmitted: true });
        return;
      }
      // Start WebAuthn immediately with minimal work beforehand (Firefox requires strict user gesture handling)
      const assertion = await startAuthentication({ 
        optionsJSON: publicKeyOptions
      });

      // 3) Send assertion to server for verification
      updateFormState({ isLoading: true, error: '' });
      const validNonce = loginNonce || (await ensureNonce());
      if (!loginNonce) setLoginNonce(validNonce);
      const verifyRes = await fetch('/api/auth/webauthn/verify', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: formState.username.trim(), nonce: validNonce, credential: assertion })
      });
      let verifyData = null;
      try { verifyData = await verifyRes.json(); } catch {}
      if (!verifyRes.ok || !verifyData?.success) {
        const message = verifyData?.message ?? 'WebAuthn verification failed';
        throw new Error(message);
      }

      // 4) Refresh auth state (server should have logged-in the session)
      await refreshAuth();
      updateFormState({ isLoading: false });
    } catch (err) {
      const diagnosticError = {
        name: err?.name,
        message: err?.message,
        code: err?.code,
        toString: err ? err.toString() : 'n/a',
        stack: err?.stack,
        isDOMException: typeof DOMException !== 'undefined' ? err instanceof DOMException : undefined,
        timestamp: new Date().toISOString(),
        isSecureContext: window.isSecureContext,
        navigatorHasCredentials: !!(navigator.credentials && navigator.credentials.get),
        pendingCredentialRequest: webauthnInProgressRef.current
      };
      console.error('[WebAuthn][client] Authentication failed', diagnosticError, err);

      // Firefox fallback: if ceremony aborted, retry once with allowCredentials forced
      const isAbort = (err?.name === 'AbortError') || (err?.code === 'ERROR_CEREMONY_ABORTED') || /aborted/i.test(err?.message ?? '');
      if (isFirefox && isAbort && !webauthnRetriedNonceRef.current) {
        try {
          webauthnRetriedNonceRef.current = true;
          const validNonce = loginNonce || (await ensureNonce());
          if (!loginNonce) setLoginNonce(validNonce);
          const res = await fetch('/api/auth/webauthn/options', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: formState.username.trim(), nonce: validNonce, forceAllowCredentials: true })
          });
          const data = await res.json().catch(() => null);
          const fallbackOptions = data?.options || data;
          if (res.ok && data?.success && fallbackOptions) {
            // Immediate retry under the same user gesture handler
            const assertion2 = await startAuthentication({ optionsJSON: fallbackOptions });
            // Verify assertion
            updateFormState({ isLoading: true, error: '' });
            const verifyRes = await fetch('/api/auth/webauthn/verify', {
              method: 'POST',
              credentials: 'include',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username: formState.username.trim(), nonce: validNonce, credential: assertion2 })
            });
            let verifyData = null;
            try { verifyData = await verifyRes.json(); } catch {}
            if (!verifyRes.ok || !verifyData?.success) {
              const message = verifyData?.message ?? 'WebAuthn verification failed';
              throw new Error(message);
            }
            await refreshAuth();
            updateFormState({ isLoading: false });
            return; // success path exits
          }
        } catch (fallbackErr) {
          console.error('[WebAuthn][client] Firefox fallback with allowCredentials failed', fallbackErr);
          // proceed to user-friendly message below
        }
      }

      // Map common WebAuthn errors to user-friendly messages
      let userFriendly = err?.message ?? 'Security Key login failed. Please try again.';
      const msg = (err?.message ?? '').toLowerCase();
      const name = (err?.name ?? '').toLowerCase();
      if (name === 'notallowederror' || msg.includes('timed out') || msg.includes('not allowed')) {
        userFriendly = 'Security key authentication was cancelled or timed out. Please, click " Back to  Sign In" to try again.';
      }

      updateFormState({
        isLoading: false,
        error: userFriendly,
        usernameSubmitted: false
      });
    } finally {
      webauthnInProgressRef.current = false;
      // Clear abort controller to avoid leaking signals
      webauthnAbortRef.current = null;
      if (typeof window !== 'undefined') {
        try { delete window.__webauthnPending; } catch {}
      }
    }
  }, [formState.step, formState.username, formState.usernameSubmitted, ensureNonce, refreshAuth, updateFormState]);

  // Auto-start WebAuthn once options are ready (no intermediate prompt) on all browsers
  useEffect(() => {
    if (formState.usernameSubmitted && formState.step === 'webauthn' && webauthnOptions && !webauthnInProgressRef.current) {
      runWebAuthnLogin();
    }
  }, [formState.usernameSubmitted, formState.step, webauthnOptions, runWebAuthnLogin]);

  // Note: We avoid global cleanup aborts here to prevent React StrictMode dev re-mount from cancelling in-flight ceremonies.
  
  return (
    <div key={`login-form-${formState.formKey}`} className="login-container">
      <div className="row justify-content-center">
        <div className="col-md-8 col-lg-6">
          <div className="card shadow-sm border-0">
            <div className="card-body p-4">
              <div className="text-center mb-4">
                <h2 className="h4 mb-1">Sign In</h2>
              </div>
              
              {/* Show error message with back button if there was a login error */}
              {(formState.hasLoginError || formState.error) && (
                <div className="mb-4">
                  <ErrorMessage 
                    error={formState.error} 
                    onBack={resetToUsernameInput} 
                  />
                </div>
              )}

              {/* Show username form by default */}
              {formState.step === 'username' && (
                <form 
                  onSubmit={async (e) => {
                    e.preventDefault();
                    if (!formState.username.trim()) {
                      updateFormState({ error: 'Please enter a username' });
                      return;
                    }
                    try {
                      updateFormState({ isLoading: true, error: '' });
                      const validNonce = await ensureNonce();
                      const result = await getLoginMethod(formState.username.trim(), validNonce);
                      if (result.method === 'webauthn') {
                        updateFormState({ 
                          usernameSubmitted: true, 
                          step: 'webauthn',
                          error: '',
                          isLoading: false,
                          password: '',
                          allowPasswordFallback: false
                        });
                        setLoginNonce(validNonce);
                      } else {
                        updateFormState({ 
                          usernameSubmitted: true, 
                          step: 'password',
                          error: '',
                          isLoading: false,
                          password: '',
                          allowPasswordFallback: true
                        });
                        setLoginNonce('');
                      }
                    } catch (err) {
                      console.error('login-method error:', err);
                      updateFormState({ 
                        error: err.message ?? 'Failed to decide login method',
                        isLoading: false
                      });
                    }
                  }}
                >
                  <div className="mb-3">
                    <input
                      id="username"
                      type="text"
                      className={`form-control ${formState.error ? 'is-invalid' : ''}`}
                      placeholder="Username"
                      value={formState.username}
                      onChange={(e) => updateFormState({ 
                        username: e.target.value, 
                        error: '' 
                      })}
                      disabled={formState.isLoading}
                      autoComplete="username"
                      autoFocus
                      aria-describedby="usernameHelp"
                    />
                    {formState.error && (
                      <div id="usernameError" className="invalid-feedback">
                        {formState.error}
                      </div>
                    )}
                  </div>
                  <button 
                    type="submit" 
                    className="btn btn-primary w-100"
                    disabled={!formState.username.trim() || formState.isLoading}
                  >
                    {formState.isLoading ? (
                      <>
                        <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                        Continuing...
                      </>
                    ) : (
                      'Continue'
                    )}
                  </button>
                </form>
              )}

              {/* Show password field when username is submitted */}
              {formState.step === 'password' && (
                <PasswordForm 
                  passwordSubmit={handlePasswordSubmit} 
                  username={formState.username} 
                  password={formState.password} 
                  setPassword={(value) => updateFormState({ password: value, error: '' })}
                  isLoading={formState.isLoading}
                  setStep={(step) => updateFormState({ step })}
                  passwordRef={passwordRef}
                  error={formState.error}
                  setError={(error) => updateFormState({ error })}
                  onBack={resetToUsernameInput}
                />
              )}

              {/* WebAuthn flow: auto-start and render minimal spinner only for all browsers */}
              {formState.usernameSubmitted && formState.step === 'webauthn' && (
                <div className="text-center">
                  {formState.isLoading && (
                    <div className="d-flex justify-content-center align-items-center">
                      <div className="spinner-border text-primary" role="status">
                        <span className="visually-hidden">Loading...</span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default LoginForm;
