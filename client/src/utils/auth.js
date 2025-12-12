// Utility function to delay execution
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// CSRF token cache
let csrfTokenCache = null;

/**
 * Gets the CSRF token from cookies
 * @returns {string|null} CSRF token or null if not found
 */
const getCsrfToken = () => {
  if (csrfTokenCache) return csrfTokenCache;
  
  const match = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
  if (match) {
    csrfTokenCache = decodeURIComponent(match[1]);
    return csrfTokenCache;
  }
  return null;
};

/**
 * Ask server which login method to use for a username
 * @param {string} username
 * @param {string} nonce
 * @returns {Promise<{success:boolean, method:'webauthn'|'password', userId?:string, username?:string}>}
 */
export const getLoginMethod = async (username, nonce) => {
  const response = await makeAuthRequest('/api/auth/login-method', {
    method: 'POST',
    body: JSON.stringify({ username, nonce }),
    credentials: 'include'
  });
  const data = await response.json();
  if (!data?.success || !data?.method) {
    throw new Error(data?.message ?? 'Failed to determine login method');
  }
  return data;
};

/**
 * Logs in the user using username/password and nonce
 * @param {string} username
 * @param {string} password
 * @param {string} nonce
 * @returns {Promise<{success: boolean, user: object}>}
 */
export const login = async (username, password, nonce) => {
  const response = await makeAuthRequest('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password, nonce }),
    credentials: 'include'
  });

  // If response.ok is false, makeAuthRequest would have thrown. But for robustness,
  // still handle unexpected non-ok here and attach code if provided.
  const data = await response.json().catch(() => null);
  if (!response.ok || !data?.success || !data?.user) {
    const message = data?.message ?? `HTTP ${response.status}`;
    const err = new Error(message);
    err.status = response.status;
    if (data?.code) err.code = data.code;
    throw err;
  }
  return data;
};

/**
 * Clears the cached CSRF token
 */
const clearCsrfToken = () => {
  csrfTokenCache = null;
};

/**
 * Makes an authenticated request
 * @param {string} url - The URL to request
 * @param {Object} options - Fetch options
 * @returns {Promise<Response>}
 */
export const makeAuthRequest = async (url, options = {}) => {
  // Get CSRF token for non-GET requests
  const csrfToken = getCsrfToken();
  
  const headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    ...(csrfToken && !['GET', 'HEAD'].includes(options.method?.toUpperCase() ?? 'GET') 
      ? { 'X-XSRF-TOKEN': csrfToken }
      : {}),
    ...(options.headers ?? {})
  };

  const defaultOptions = {
    credentials: 'include',
    headers,
    ...options
  };

  try {
    const response = await fetch(url, defaultOptions);
    
    // Handle 401 Unauthorized - clear user session
    if (response.status === 401) {
      // Clear any cached CSRF token
      clearCsrfToken();
      // Let the caller handle the 401
      const error = new Error('Session expired or invalid');
      error.status = 401;
      throw error;
    }
    
    // Handle other error statuses
    if (!response.ok) {
      const error = new Error(`HTTP error! status: ${response.status}`);
      error.status = response.status;
      error.response = response;
      throw error;
    }
    
    return response;
  } catch (error) {
    // Enhance network errors with more context
    if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
      error.message = 'Network error: Unable to connect to the server';
      error.status = 0; // Network error
    }
    throw error;
  }
};

/**
 * Checks if the current user is authenticated
 * @returns {Promise<{authenticated: boolean, user: Object|null}>}
 */
export const checkAuthStatus = async () => {
  try {
    const response = await makeAuthRequest('/api/auth/me');
    const data = await response.json();
    
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid server response format');
    }
    
    return { 
      authenticated: Boolean(data.authenticated && data.user),
      user: data.user ?? null
    };
  } catch (error) {
    if (error.status === 401) {
      // Session expired or invalid
      return { authenticated: false, user: null };
    }
    
    // Re-throw other errors to be handled by the caller
    console.error('Auth check failed:', error);
    throw error;
  }
};

/**
 * Logs out the current user by invalidating the server session
 * @returns {Promise<{success: boolean, message: string}>}
 */
export const logout = async () => {
  try {
    const response = await makeAuthRequest('/api/auth/logout', {
      method: 'POST',
      credentials: 'include'
    });

    if (!response.ok) {
      throw new Error(`Logout failed: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Logout error:', error);
    throw error;
  }
};
