import express from 'express';
import { 
  getProfile, 
  updateProfile,
  verifyUpdatedEmail,
  resendEmailVerification
} from '../controllers/profileController.js';
import authenticateToken from '../middleware/authMiddleware.js';

const router = express.Router();

// All profile routes require authentication
router.use(authenticateToken);

// 6.3.1 Get Profile API
router.get('/profile', getProfile);

// 6.3.2 Update Profile API
router.put('/update', updateProfile);

// Email verification for updated email
router.post('/verify-email', verifyUpdatedEmail);
router.post('/resend-verification', resendEmailVerification);

export default router;