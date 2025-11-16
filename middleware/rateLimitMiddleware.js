import rateLimit from 'express-rate-limit';

// Simple, working rate limiters without deprecated options

// Rate limit for password reset OTP
export const passwordResetLimiter = rateLimit({
  windowMs: 2 * 60 * 1000, // 2 minutes
  max: 15, // 16 request per 2 minutes
  message: {
    success: false,
    message: 'Too many password reset attempts. Please try again in 2 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limit for signup
export const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 15, // 15 requests per hour
  message: {
    success: false,
    message: 'Too many signup attempts. Please try again in an hour.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limit for OTP verification
export const otpVerificationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // 15 requests per 15 minutes
  message: {
    success: false,
    message: 'Too many OTP verification attempts. Please try again in 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limit for signin attempts
export const signinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // 15 attempts per 15 minutes
  message: {
    success: false,
    message: 'Too many signin attempts. Please try again in 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Global API rate limiter
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // 1000 requests per 15 minutes
  message: {
    success: false,
    message: 'Too many API requests. Please slow down.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});