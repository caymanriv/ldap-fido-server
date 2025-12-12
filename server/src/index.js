// Dependencies
import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import { v4 as uuidv4 } from 'uuid';
import passport from 'passport';
import { getUserById, getUserByUsername, createUserWithRole } from './db/userOps.js';
import adminRoutes from './routes/admin.js';
import appVarsRoutes from './routes/appVars.js';

// Local imports
import rateLimit from './middlewares/rateLimit.js';
import { configureSession } from './config/session.js';
import { logger } from './utils/logger.js';
 

// Configuration
import dotenv from 'dotenv';
dotenv.config();

// Constants
const SERVER_PORT = parseInt(process.env.SERVER_DEFAULT_PORT, 10);

// Function to get allowed CORS origins
function getAllowedOrigins() {
  let corsOrigins = [];
  try {
    corsOrigins = (process.env.SERVER_CORS_ORIGIN)
      .split(',')
      .map(o => o.trim())
      .filter(origin => {
        try {
          if (origin === '*') return true;
          new URL(origin);
          return true;
        } catch (e) {
          console.error(`Invalid CORS origin '${origin}':`, e.message);
          return false;
        }
      });
    
    console.log('Allowed CORS origins:', corsOrigins);
    return corsOrigins;
  } catch (error) {
    console.error('Error parsing CORS_ORIGINS:', error);
    const defaultOrigins = ['http://localhost:5173', 'http://rpid.example.org:5173'];
    console.log('Falling back to default CORS origins:', defaultOrigins);
    return defaultOrigins;
  }
}

// Initialize Express app
const app = express();

/**
 * Starts the Express server
 */
async function startServer() {
  try {
    // Configure session and get middleware
    let sessionMiddleware, securityHeaders, sessionContext, redisClient = null, sessionSave;
    try {
      const sessionConfig = await configureSession();
      sessionMiddleware = sessionConfig.session;
      securityHeaders = sessionConfig.securityHeaders;
      sessionContext = sessionConfig.sessionContext;
      sessionSave = sessionConfig.sessionSave; // Get the session save middleware
      // Store redisClient in app.locals for access in routes
      app.locals.redisClient = sessionConfig.redisClient;
      redisClient = sessionConfig.redisClient; // Store redisClient for later use
      console.log('Session configuration loaded successfully');
    } catch (error) {
      console.error('Failed to configure session:', error);
      if (error.message.includes('Redis')) {
        console.error('\n=== REDIS CONNECTION ERROR ===');
        console.error('Please check your Redis configuration:');
        console.error(`- REDIS_HOST: ${process.env.REDIS_HOST ?? 'redis (default)'}`);
        console.error(`- REDIS_PORT: ${process.env.REDIS_PORT ?? '6379 (default)'}`);
        console.error(`- REDIS_DB: ${process.env.REDIS_DB ?? '0 (default)'}`);
        console.error('Make sure Redis is running and accessible from the server.');
        console.error('================================\n');
      }
      throw error; // Re-throw to be caught by the outer try-catch
    }

    // CORS configuration
    console.log('Configuring CORS...');
    const CORS_ORIGINS = getAllowedOrigins();
    
    // Create CORS middleware
    const corsMiddleware = (req, res, next) => {
      const origin = req.headers.origin;
      const requestMethod = req.method;
      const requestHeaders = req.headers['access-control-request-headers'];
      
      // Log CORS request for debugging
      logger.debug(`CORS request from origin: ${origin ?? 'none'}, method: ${requestMethod}`);
      
      // Always set Vary header for proper caching
      res.header('Vary', 'Origin');
      
      // Handle preflight requests
      if (requestMethod === 'OPTIONS') {
        // Allow all origins for preflight
        res.header('Access-Control-Allow-Origin', origin ?? '*');
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
        res.header('Access-Control-Allow-Headers', requestHeaders ? requestHeaders.split(',').map(header => header.trim()).filter(header => header) : []);
        res.header('Access-Control-Max-Age', '86400'); // 24 hours
        return res.status(204).end();
      }
      
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) {
        return next();
      }
      
      try {
        // Check if origin is allowed
        const isAllowedOrigin = CORS_ORIGINS.some(allowedOrigin => {
          if (allowedOrigin === '*') return true;
          try {
            return origin === allowedOrigin || 
                   new URL(origin).hostname === new URL(allowedOrigin).hostname;
          } catch (e) {
            console.error(`Error comparing origins '${origin}' and '${allowedOrigin}':`, e.message);
            return false;
          }
        });
        
        if (isAllowedOrigin) {
          res.header('Access-Control-Allow-Origin', origin);
          res.header('Access-Control-Allow-Credentials', 'true');
          return next();
        }
        
        // Origin not allowed
        console.warn(`Blocked request from unauthorized origin: ${origin}`);
        console.log('Allowed origins:', CORS_ORIGINS);
        return res.status(403).json({ 
          error: 'Forbidden',
          message: `The CORS policy for this site does not allow access from the specified origin: ${origin}`,
          allowedOrigins: CORS_ORIGINS
        });
      } catch (error) {
        console.error('Error processing CORS request:', error);
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'An error occurred while processing the CORS request'
        });
      }
    };
    
    // Apply CORS middleware
    app.use(corsMiddleware);
    console.log('CORS middleware applied successfully');

    // Security & logging
    console.log('Configuring security headers...');
    app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'"],
          connectSrc: ["'self'", ...(process.env.SERVER_CORS_ORIGIN?.split(',') ?? ['http://localhost:5173'])]
        }
      },
      crossOriginResourcePolicy: { policy: "cross-origin" },
      crossOriginOpenerPolicy: { policy: "same-origin" },
      hsts: {
        maxAge: 63072000, // 2 years in seconds
        includeSubDomains: true,
        preload: true
      }
    }));
    console.log('Security headers configured successfully');
    
    app.use(rateLimit);
    console.log('Rate limiting configured successfully');
    
    app.use(morgan('dev'));
    console.log('Logging configured successfully');

    // Body parsing
    console.log('Configuring body parsing...');
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    console.log('Body parsing configured successfully');

    // Trust proxy for correct cookie/session handling behind Docker/proxy
    console.log('Configuring trust proxy...');
    app.set('trust proxy', 1);
    console.log('Trust proxy configured successfully');
    
    // Add request ID and logging
    console.log('Configuring request ID and logging...');
    app.use((req, res, next) => {
      req.id = uuidv4();
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} [${req.id}]`);
      next();
    });
    console.log('Request ID and logging configured successfully');

    // Apply session and security middlewares
    console.log('Configuring session and security middlewares...');
    
    // Debug middleware to log session state
    app.use((req, res, next) => {
      logger.debug('=== SESSION DEBUG ===');
      logger.debug('Request headers:', {
        cookie: req.headers.cookie ? 'present' : 'missing',
        origin: req.headers.origin,
        host: req.headers.host,
        'user-agent': req.headers['user-agent']
      });
      next();
    });
    
    // Session middleware must be first
    app.use(sessionMiddleware);
    
    // Debug middleware after session is loaded
    app.use((req, res, next) => {
      logger.debug('=== SESSION DEBUG ===');
      logger.debug('Session ID:', req.sessionID);
      logger.debug('Session cookie:', req.session.cookie);
      logger.debug('Session data:', {
        user: req.user ?? 'No user',
        isAuthenticated: req.isAuthenticated ? req.isAuthenticated() : 'Not authenticated'
      });
      next();
    });
    
    // Load Passport configuration (serialize/deserialize) BEFORE initializing passport
    console.log('Importing Passport configuration...');
    try {
      await import('./config/passport.js');
      console.log('Passport configuration loaded successfully');
    } catch (error) {
      console.error('Failed to load Passport configuration:', error);
      throw error;
    }
    
    // Configure LDAP authentication BEFORE using passport middlewares
    console.log('Configuring LDAP authentication...');
    const { configureLdapAuth } = await import('./utils/ldapClient.js');
    try {
      configureLdapAuth(passport);
      console.log('LDAP authentication configured successfully');
    } catch (error) {
      console.error('Failed to configure LDAP authentication:', error);
      throw error; // Prevent server from starting if LDAP config fails
    }
    
    // Initialize Passport and restore authentication state from session
    app.use(passport.initialize());
    
    // Debug middleware after passport initialize
    app.use((req, res, next) => {
      logger.debug('After passport.initialize()');
      logger.debug('Is authenticated (pre-session):', req.isAuthenticated ? req.isAuthenticated() : 'req.isAuthenticated not a function');
      logger.debug('User (pre-session):', req.user);
      next();
    });
    
    app.use(passport.session());
    
    // Debug middleware after passport session
    app.use((req, res, next) => {
      logger.debug('After passport.session()');
      logger.debug('Is authenticated (post-session):', req.isAuthenticated ? req.isAuthenticated() : 'req.isAuthenticated not a function');
      logger.debug('User (post-session):', req.user);
      next();
    });
    
    // Security headers
    app.use(securityHeaders);
    
    // Session context for logging
    app.use(sessionContext);
    
    // Session save middleware - ensure session is saved
    app.use((req, res, next) => {
      const originalEnd = res.end;
      res.end = function(chunk, encoding) {
        logger.debug('Saving session before response end');
        // Save session before ending the response
        if (req.session && typeof req.session.save === 'function') {
          req.session.save((err) => {
            if (err) {
              console.error('Error saving session:', err);
            }
            logger.debug('Session saved successfully');
            originalEnd.call(res, chunk, encoding);
          });
        } else {
          logger.debug('No session to save');
          originalEnd.call(res, chunk, encoding);
        }
      };
      next();
    });
    
    // (Passport config and LDAP auth were initialized above before passport.initialize())

    // Only set up Redis error handling if redisClient exists
    if (redisClient) {
      console.log('Configuring Redis error handling...');
      redisClient.on('error', (err) => {
        console.error('Redis error:', err);
      });

      redisClient.on('reconnecting', () => {
        console.log('Reconnecting to Redis...');
      });

      redisClient.on('ready', () => {
        console.log('Redis client is ready');
      });
    } else {
      console.log('Skipping Redis configuration (using MemoryStore)');
    }

      // API Routes - Import and mount after all middleware is configured
    console.log('Configuring API routes...');
    const authRoutes = (await import('./routes/auth.js')).default;
    const webauthnRoutes = (await import('./routes/webauthn.js')).default;
    
    // Register API routes with explicit paths
    app.use('/api/auth', authRoutes);
    app.use('/api/webauthn', webauthnRoutes);
    console.log('API routes configured successfully');

    // Admin routes (protected by admin middleware)
    app.use('/api', adminRoutes);

    // App variables admin routes used by the frontend Admin page
    // This serves endpoints like GET /admin/app-vars and PUT /admin/app-vars/:service
    app.use('/admin', appVarsRoutes);

    // API health check with detailed information
    app.get('/api/health', async (req, res) => {
      try {
        const health = {
          status: 'ok',
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          environment: process.env.NODE_ENV ?? 'development',
          services: {
          redis: req.app.locals.redisClient ? 
            (req.app.locals.redisClient.status === 'ready' ? 'ok' : 'error') : 
            'not configured',
          database: 'ok' // Assuming database is up if we got this far
        }
      };
      
      res.json(health);
    } catch (error) {
      console.error('Health check failed:', error);
      res.status(500).json({
        status: 'error',
        message: 'Health check failed',
        error: error.message,
        ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
      });
    }
  });
  
  // Legacy health check endpoint (for backward compatibility)
  app.get('/health', (req, res) => {
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV ?? 'development'
    });
  });
  
  // Error handling middleware - should be after all other middleware and routes
  app.use((err, req, res, next) => {
    console.error('Unhandled error:', {
      error: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
      path: req.path,
      method: req.method
    });

    // Default error status and message
    const status = err.status ?? 500;
    const message = err.message ?? 'Internal Server Error';

    // Prepare error response
    const errorResponse = {
      error: true,
      status,
      message,
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    };

    // Handle specific error types
    if (err.name === 'ValidationError') {
      errorResponse.errors = Object.values(err.errors).map(e => e.message);
    }

    // Send error response
    res.status(status).json(errorResponse);
  });

      // 404 handler - must be after all other routes
      app.use((req, res) => {
        res.status(404).json({
          error: 'Not Found',
          message: `The requested resource ${req.originalUrl} was not found`
        });
      });

      // Start the server
      return new Promise((resolve, reject) => {
        const server = app.listen(SERVER_PORT, (err) => {
          if (err) {
            console.error('Failed to start server:', err);
            return reject(err);
          }
          console.log(`Server is running on port ${SERVER_PORT}`);
          resolve(server);
        });
      });
    } catch (error) {
      console.error('Failed to start server:', error);
      throw error; // Re-throw to be caught by the outer catch
    }
  } // End of startServer function

  // Start the server and handle any initialization errors
  startServer()
    .then(() => {
      console.log('Server started successfully');
    })
    .catch(error => {
      console.error('Failed to start server:', error);
      process.exit(1);
    });
