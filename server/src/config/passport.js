import passport from 'passport';
import { getUserById, getUserByUsername } from '../db/userOps.js';
import { logger } from '../utils/logger.js';

// Serialize user to the session
passport.serializeUser((user, done) => {
  logger.debug('=== PASSPORT SERIALIZE USER ===');
  logger.debug('User object to serialize:', JSON.stringify({
    id: user?.id,
    username: user?.username,
    isAdmin: user?.isAdmin,
    roles: user?.roles,
    isTemporary: user?.isTemporary
  }, null, 2));
  
  try {
    if (!user) {
      console.error('No user object provided to serializeUser');
      return done(new Error('No user object provided'));
    }
    
    // We should always have an ID by this point (either from DB or a temporary one)
    if (!user.id) {
      console.error('No ID found for user during serialization');
      return done(new Error('No ID found for user'));
    }
    
    // Store the minimum required information in the session
    const sessionData = { 
      id: user.id,
      username: user.username,
      isAdmin: user.isAdmin || false,
      roles: user.roles || [],
      isTemporary: user.isTemporary || false,
      // Add any other minimal user data needed for deserialization
      ...(user.email && { email: user.email }),
      ...(user.displayName && { displayName: user.displayName })
    };
    
    logger.debug('Serialized user data for session:', JSON.stringify(sessionData, null, 2));
    done(null, sessionData);
  } catch (error) {
    console.error('Error during serialization:', error);
    done(error);
  }
});

// Deserialize user from the session
passport.deserializeUser(async (sessionUser, done) => {
  logger.debug('=== PASSPORT DESERIALIZE USER ===');
  logger.debug('Raw session data:', JSON.stringify(sessionUser, null, 2));
  
  try {
    if (!sessionUser) {
      logger.debug('No session user data found');
      return done(null, false);
    }
    
    logger.debug('Session data type:', typeof sessionUser);
    logger.debug('Session data keys:', Object.keys(sessionUser));
    
    // Handle case where sessionUser is a string (legacy format)
    if (typeof sessionUser === 'string') {
      logger.debug('Legacy session format detected, migrating...');
      
      // Try to get by ID (UUID)
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(sessionUser)) {
        try {
          const user = await getUserById(sessionUser);
          if (user) {
            const userForSession = {
              id: user.id,
              username: user.username,
              email: user.email,
              displayName: user.displayName,
              isAdmin: user.roles && user.roles.includes('admin'),
              roles: user.roles || []
            };
            logger.debug('Deserialized legacy user by ID:', userForSession);
            return done(null, userForSession);
          }
        } catch (error) {
          console.error('Error fetching user by ID during deserialization:', error);
          // Continue to try other methods
        }
      }
      
      // If not found by ID, try by username
      try {
        const user = await getUserByUsername(sessionUser);
        if (user) {
          const userForSession = {
            id: user.id,
            username: user.username,
            email: user.email,
            displayName: user.displayName,
            isAdmin: user.roles && user.roles.includes('admin'),
            roles: user.roles || []
          };
          logger.debug('Deserialized legacy user by username:', userForSession);
          return done(null, userForSession);
        }
      } catch (error) {
        console.error('Error fetching user by username during deserialization:', error);
      }
      
      console.error('User not found during legacy deserialization');
      return done(null, false);
    }
    
    // Handle object session data (new format)
    if (typeof sessionUser === 'object' && sessionUser !== null) {
      // If this is a temporary user (starts with 'temp_')
      if (typeof sessionUser.id === 'string' && sessionUser.id.startsWith('temp_')) {
        logger.debug('Deserializing temporary user');
        return done(null, {
          id: sessionUser.id,
          username: sessionUser.username,
          isTemporary: true,
          roles: [],
          // Preserve any additional session data
          ...sessionUser
        });
      }
      
      // If we already have the user data in the session (from serializeUser)
      if (sessionUser.id && sessionUser.username) {
        logger.debug('Using user data from session');
        const userData = {
          id: sessionUser.id,
          username: sessionUser.username,
          isAdmin: sessionUser.isAdmin || false,
          roles: sessionUser.roles || [],
          isTemporary: sessionUser.isTemporary || false,
          // Add any other properties that might be needed
          ...(sessionUser.email && { email: sessionUser.email }),
          ...(sessionUser.displayName && { displayName: sessionUser.displayName })
        };
        logger.debug('Deserialized user:', JSON.stringify(userData, null, 2));
        return done(null, userData);
      }
      
      // If we don't have enough data in the session, try to get from database
      if (sessionUser.id) {
        try {
          const dbUser = await getUserById(sessionUser.id);
          if (dbUser) {
            const userForSession = {
              id: dbUser.id,
              username: dbUser.username,
              email: dbUser.email,
              displayName: dbUser.displayName,
              isAdmin: dbUser.roles && dbUser.roles.includes('admin'),
              roles: dbUser.roles || []
            };
            console.log('Deserialized user from database:', userForSession);
            return done(null, userForSession);
          }
        } catch (error) {
          console.error('Error fetching user from database during deserialization:', error);
        }
      }
      
      console.error('Insufficient data to deserialize user from session');
      return done(null, false);
    }
    
    console.error('Invalid session data format during deserialization');
    return done(null, false);
  } catch (error) {
    console.error('Error during deserialization:', error);
    return done(error);
  }
});

export default passport;
