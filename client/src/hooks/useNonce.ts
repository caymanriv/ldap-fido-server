import { useState, useCallback, useRef, useEffect } from 'react';

const useNonce = () => {
  const [nonce, setNonce] = useState<string | null>(null);
  const nonceRequest = useRef<Promise<string | null> | null>(null);

  const refreshNonce = useCallback(async (): Promise<string | null> => {
    if (nonceRequest.current) {
      return nonceRequest.current;
    }

    nonceRequest.current = (async () => {
      try {
        // Add a timeout to avoid hanging
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);
        const res = await fetch('/api/auth/nonce', { 
          credentials: 'include',
          headers: { 'Cache-Control': 'no-cache' },
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        
        if (!res.ok) {
          throw new Error('Failed to fetch nonce');
        }
        
        const data = await res.json();
        const newNonce = data.nonce;
        
        if (typeof newNonce === 'string') {
          setNonce(newNonce);
          return newNonce;
        }
        
        throw new Error('Invalid nonce format');
      } catch (error) {
        console.error('Error refreshing nonce:', error);
        return null;
      } finally {
        nonceRequest.current = null;
      }
    })();

    return nonceRequest.current;
  }, []);

  // Initial nonce fetch on mount and cleanup
  useEffect(() => {
    let isMounted = true;
    
    const fetchNonce = async () => {
      try {
        await refreshNonce();
      } catch (error) {
        if (isMounted) {
          console.error('Failed to fetch initial nonce:', error);
        }
      }
    };
    
    fetchNonce();
    
    return () => {
      isMounted = false;
    };
  }, [refreshNonce]);

  return { nonce, refreshNonce };
};

export default useNonce;
