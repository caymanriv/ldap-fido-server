import rateLimit from 'express-rate-limit';

// Check if we're in development mode
const isDev = process.env.NODE_ENV === 'development';

// Skip rate limiting for these paths
const skipPaths = [
  '/health',
  '/api/health',
  '/api/auth/me',
  '/api/auth/nonce'
];

const rateLimitConfig = {
  windowMs: isDev ? 5 * 60 * 1000 : 15 * 60 * 1000, // 5 minutes in dev, 15 in prod
  max: isDev ? 1000 : 100, // More lenient in development
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for health checks and specific paths
    if (skipPaths.some(path => req.path.startsWith(path))) {
      return true;
    }
    
    // Skip rate limiting for localhost in development
    if (isDev && (req.ip === '127.0.0.1' || req.ip === '::1' || req.ip === '::ffff:127.0.0.1')) {
      return true;
    }
    
    return false;
  },
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many requests, please try again later.'
    });
  }
};

// If we're in development, log the rate limiting configuration
if (isDev) {
  console.log('Rate limiting configuration:', {
    enabled: true,
    windowMs: rateLimitConfig.windowMs,
    max: rateLimitConfig.max,
    skipPaths
  });
}

const limiter = rateLimit(rateLimitConfig);

export default limiter;
