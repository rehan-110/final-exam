import express from 'express';
import { 
  signUp, 
  verifyOTP, 
  resendOTP, 
  signIn, 
  getProfile,
  forgotPassword,
  verifyResetOTP,
  resetPassword,
  refreshToken, // ADD THIS
  logout, // ADD THIS
  logoutAll // ADD THIS
} from '../controllers/authController.js';
import authenticateToken from '../middleware/authMiddleware.js';
import { 
  passwordResetLimiter, 
  signupLimiter, 
  otpVerificationLimiter 
} from '../middleware/rateLimitMiddleware.js';

const router = express.Router();

// Public routes with rate limiting
router.post('/signup', signupLimiter, signUp);
router.post('/verify-otp', otpVerificationLimiter, verifyOTP);
router.post('/resend-otp', otpVerificationLimiter, resendOTP);
router.post('/signin', signIn);
router.post('/forgot-password', passwordResetLimiter, forgotPassword);
router.post('/verify-reset-otp', otpVerificationLimiter, verifyResetOTP);
router.post('/reset-password', resetPassword);

// NEW ROUTES FOR REFRESH TOKEN FUNCTIONALITY
router.post('/refresh-token', refreshToken);
router.post('/logout', logout);
router.post('/logout-all', logoutAll);

// Protected routes
router.get('/profile', authenticateToken, getProfile);

export default router;