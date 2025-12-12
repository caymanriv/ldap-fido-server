import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { checkAuthStatus, logout as apiLogout, login as apiLogin } from '../utils/auth';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [lastChecked, setLastChecked] = useState(0);
  const checkInProgress = React.useRef(false);

  // Handle successful login
  const handleLogin = useCallback((userData) => {
    const userWithRoles = {
      ...userData,
      roles: userData.roles || (userData.isAdmin ? ['admin'] : ['user']),
      isAdmin: userData.isAdmin || (Array.isArray(userData.roles) && userData.roles.includes('admin'))
    };
    setUser(userWithRoles);
    setLastChecked(Date.now());
    return userWithRoles;
  }, []);

  // Check authentication status
  const verifyAuth = useCallback(async (force = false) => {
    // Skip if a check is already in progress
    if (checkInProgress.current && !force) {
      return user;
    }

    // Skip if we've checked recently (within 5 seconds) unless forced
    const now = Date.now();
    if (!force && now - lastChecked < 5000) {
      return user;
    }

    checkInProgress.current = true;
    setIsLoading(true);

    try {
      const { authenticated, user: authUser } = await checkAuthStatus();
      
      if (authenticated && authUser) {
        // If we have a user, ensure we have all required fields
        if (!authUser.roles || !authUser.username) {
          console.error('Incomplete user data received from server');
          setUser(null);
          return null;
        }
        return handleLogin(authUser);
      } else {
        // Only update state if we're sure the user is not authenticated
        if (user !== null) {
          setUser(null);
        }
        return null;
      }
    } catch (error) {
      console.error('Auth verification error:', error);
      // On network errors, only update state if we don't have a user
      if (!user) {
        setUser(null);
      }
      return user;
    } finally {
      checkInProgress.current = false;
      setIsLoading(false);
      setLastChecked(now);
    }
  }, [user, lastChecked, handleLogin]);

  // Initial auth check on app load
  useEffect(() => {
    verifyAuth();
  }, []);

  // Refresh auth state
  const refreshAuth = useCallback(() => {
    return verifyAuth(true);
  }, [verifyAuth]);

  // Perform real backend login, then set user state
  const performLogin = useCallback(async (username, password, nonce) => {
    const { user: serverUser } = await apiLogin(username, password, nonce);
    return handleLogin(serverUser);
  }, [handleLogin]);

  const logout = useCallback(async () => {
    try {
      await apiLogout();
    } catch (error) {
      console.error('Error during logout:', error);
      // Continue with client-side cleanup even if server logout fails
    } finally {
      // Clear local state
      setUser(null);
      setLastChecked(0);
    }
  }, []);

  const value = {
    user,
    isLoading,
    isAuthenticated: !!user,
    isAdmin: user?.isAdmin || false,
    login: performLogin,
    logout,
    refreshAuth
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
