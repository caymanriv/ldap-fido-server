import session from 'express-session';
import { v4 as uuidv4 } from 'uuid';
import RedisStore from 'connect-redis';
import { createClient as createRedisClient } from 'redis';

// Constants
const SESSION_CONFIG = {
  PREFIX: 'sess:',
  TTL: 60 * 60 * 24 * 7, // 7 days in seconds
  COOKIE: {
    NAME: 'ldap-fido.sid',
    PATH: '/',
    HTTP_ONLY: true,
    SECURE: process.env.NODE_ENV === 'production', // Auto-set based on environment
    SAME_SITE: process.env.NODE_ENV === 'production' ? 'lax' : 'lax',
    MAX_AGE: 7 * 24 * 60 * 60 * 1000, // 7 days to match TTL
    DOMAIN: process.env.NODE_ENV === 'production' && process.env.SESSION_COOKIE_DOMAIN 
      ? process.env.SESSION_COOKIE_DOMAIN.replace(/^(https?:\/\/)?([^/]+).*$/, '$2')
      : undefined,
    SAME_SITE_COOKIE: process.env.NODE_ENV === 'production' ? 'lax' : 'lax',
    SECURE_COOKIE: process.env.NODE_ENV === 'production'
  },
  SECRET: process.env.SERVER_SESSION_SECRET ?? 'change_this_secret',
  REDIS: {
    HOST: process.env.REDIS_HOST ?? 'redis',
    PORT: parseInt(process.env.REDIS_PORT ?? '6379'),
    DB: parseInt(process.env.REDIS_DB ?? '0'),
    PASSWORD: (typeof process.env.REDIS_PASSWORD === 'string' && process.env.REDIS_PASSWORD.length)
      ? process.env.REDIS_PASSWORD
      : undefined,
  },
  SECURITY_HEADERS: {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'"
  }
};

/**
 * Creates and configures the session store
 * @returns {Promise<Object>} Configured session store
 */
async function createSessionStore() {
  try {
    const redisClient = createRedisClient({
      socket: {
        host: SESSION_CONFIG.REDIS.HOST,
        port: SESSION_CONFIG.REDIS.PORT
      },
      database: SESSION_CONFIG.REDIS.DB,
      password: SESSION_CONFIG.REDIS.PASSWORD
    });

    // Connect the Redis client
    await redisClient.connect();
    console.log('Connected to Redis for session storage');

    // Create Redis session store
    const store = new RedisStore({
      client: redisClient,
      prefix: SESSION_CONFIG.PREFIX,
      ttl: SESSION_CONFIG.TTL
    });

    return { store, redisClient };
  } catch (error) {
    console.error('Failed to create session store:', error);
    throw error;
  }
}

/**
 * Configures and returns session middleware
 * @returns {Promise<Object>} Session middleware and Redis client
 */
async function configureSession() {
  try {
    const { store, redisClient } = await createSessionStore();

    // Configure session middleware
    const sessionMiddleware = session({
      name: SESSION_CONFIG.COOKIE.NAME ?? 'connect.sid',
      store,
      secret: SESSION_CONFIG.SECRET ?? 'fallback-secret-key-change-me',
      resave: false,
      saveUninitialized: false,
      rolling: true, // Reset maxAge on every request
      proxy: process.env.NODE_ENV === 'production', // Trust reverse proxy in production
      genid: () => uuidv4(),
      cookie: {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // true in production for HTTPS
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week
        // Explicitly set domain for cross-subdomain cookies if needed
        // domain: process.env.COOKIE_DOMAIN || 'localhost'
      },
      // Force the session to be saved back to the session store
      // even if the session was never modified during the request
      saveUninitialized: false,
      // Forces the session to be saved back to the session store
      // even if the session was never modified during the request
      resave: false
    });

    // Add security headers middleware
    const securityHeaders = (req, res, next) => {
      Object.entries(SESSION_CONFIG.SECURITY_HEADERS).forEach(([header, value]) => {
        res.setHeader(header, value);
      });
      next();
    };

    // Session context middleware
    const sessionContext = (req, res, next) => {
      // Add session ID to response locals for logging
      res.locals.sessionId = req.sessionID;

      if (req.session) {
        try {
          const now = new Date().toISOString();
          const forwarded = req.headers['x-forwarded-for'];
          const forwardedValue = Array.isArray(forwarded) ? forwarded[0] : forwarded;
          const resolvedIp = () => {
            if (typeof forwardedValue === 'string' && forwardedValue.length) {
              const first = forwardedValue.split(',')[0].trim();
              if (first.length) return first;
            }
            return req.ip;
          };
          const ip = resolvedIp();
          const userAgent = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : 'unknown';
          const acceptLanguage = typeof req.headers['accept-language'] === 'string' ? req.headers['accept-language'] : undefined;
          const secureProto = Boolean(req.secure || req.headers['x-forwarded-proto'] === 'https' || req.connection?.encrypted);

          const hintHeaders = [
            'sec-ch-ua',
            'sec-ch-ua-full-version',
            'sec-ch-ua-platform',
            'sec-ch-ua-platform-version',
            'sec-ch-ua-arch',
            'sec-ch-ua-model',
            'sec-ch-ua-mobile'
          ];
          const mergedHints = { ...(req.session.securityContext?.clientHints ?? {}) };
          hintHeaders.forEach((header) => {
            const value = req.headers[header];
            if (typeof value === 'string' && value.length) {
              mergedHints[header] = value;
            }
          });
          const clientHints = Object.keys(mergedHints).length ? mergedHints : undefined;

          const previous = req.session.securityContext ?? {};

          req.session.securityContext = {
            createdAt: previous.createdAt ?? now,
            createdIp: previous.createdIp ?? ip,
            createdUserAgent: previous.createdUserAgent ?? userAgent,
            createdAcceptLanguage: previous.createdAcceptLanguage ?? acceptLanguage,
            createdIsSecureConnection: previous.createdIsSecureConnection ?? secureProto,
            lastSeenAt: now,
            lastIp: ip,
            lastUserAgent: userAgent,
            lastAcceptLanguage: acceptLanguage,
            lastIsSecureConnection: secureProto,
            clientHints
          };
        } catch (sessionError) {
          console.error('Session security context update failed:', sessionError);
        }
      }

      next();
    };

    return {
      session: sessionMiddleware,
      securityHeaders,
      sessionContext,
      sessionSave: (req, res, next) => {
        // Save the session before sending the response
        req.session.save((err) => {
          if (err) {
            console.error('Session save error:', err);
          }
          next();
        });
      },
      redisClient
    };
  } catch (error) {
    console.error('Error configuring session:', error);
    throw error;
  }
}

export { configureSession };

