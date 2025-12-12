import { useState, useCallback, useRef, useEffect } from 'react';
import { logger } from '../utils/logger';

export default function useNonce() {
  const [nonce, setNonce] = useState('');
  const [error, setError] = useState(null);
  const noncePromise = useRef(null);
  const isMounted = useRef(true);
  const retryCount = useRef(0);
  const maxRetries = 3;
  const retryDelay = 1000; // 1 second

  // Initialize nonce on mount
  useEffect(() => {
    refreshNonce();
    return () => {
      isMounted.current = false;
    };
  }, []);

  const refreshNonce = useCallback(async () => {
    // If there's already a nonce request in progress, return that promise
    if (noncePromise.current) {
      return noncePromise.current;
    }

    // Create a new promise for the nonce request
    noncePromise.current = (async () => {
      try {
        const response = await fetch('/api/auth/nonce', {
          method: 'GET',
          credentials: 'include', // Important for session cookies
          cache: 'no-store', // Prevent caching of the nonce
          headers: {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Accept': 'application/json'
          }
        });
        
        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(`Failed to fetch nonce: ${response.status} ${response.statusText} - ${errorText}`);
        }
        
        const data = await response.json();
        
        if (!data.nonce) {
          throw new Error('Invalid nonce received from server');
        }
        
        if (isMounted.current) {
          setNonce(data.nonce);
          setError(null);
          retryCount.current = 0; // Reset retry count on success
        }
        return data.nonce;
      } catch (error) {
        console.error('Failed to refresh nonce:', error);
        
        // Only update state if component is still mounted
        if (isMounted.current) {
          setError(error.message);
          
          // Retry logic
          if (retryCount.current < maxRetries) {
            retryCount.current += 1;
            logger.debug(`Retrying nonce fetch (attempt ${retryCount.current}/${maxRetries})...`);
            await new Promise(resolve => setTimeout(resolve, retryDelay * retryCount.current));
            return refreshNonce(); // Recursively retry
          }
          
          // Fallback to client-side nonce if server is unavailable after retries
          const fallbackNonce = Math.random().toString(36).substring(2, 15) + 
                              Math.random().toString(36).substring(2, 15);
          setNonce(fallbackNonce);
          return fallbackNonce;
        }
      } finally {
        // Clear the current promise when done
        noncePromise.current = null;
      }
    })();

    return noncePromise.current;
  }, []);

  // Return the current nonce, error, and refresh function
  return { 
    nonce, 
    error,
    refreshNonce,
    // Helper to ensure we have a valid nonce before making a request
    ensureNonce: async () => {
      if (!nonce || error) {
        return await refreshNonce();
      }
      return nonce;
    }
  };
}
