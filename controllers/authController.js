import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import validator from 'validator';
import { generateOTP, sendVerificationEmail, sendPasswordResetEmail } from '../utils/emailService.js';

// Enhanced validation functions
const validateName = (name) => {
  if (!name || name.trim().length < 2) {
    return 'Name must be at least 2 characters long';
  }
  if (name.trim().length > 50) {
    return 'Name must be less than 50 characters';
  }
  if (!/^[a-zA-Z\s]+$/.test(name.trim())) {
    return 'Name can only contain letters and spaces';
  }
  return null;
};

const validateEmail = (email) => {
  if (!email) {
    return 'Email is required';
  }
  if (!validator.isEmail(email)) {
    return 'Please provide a valid email address';
  }
  if (!validator.isLength(email, { max: 100 })) {
    return 'Email must be less than 100 characters';
  }
  return null;
};

const validatePassword = (password) => {
  if (!password) {
    return 'Password is required';
  }
  if (password.length < 6) {
    return 'Password must be at least 6 characters long';
  }
  if (password.length > 100) {
    return 'Password must be less than 100 characters';
  }
  if (!validator.isStrongPassword(password, { 
    minLength: 6,
    minLowercase: 1,
    minUppercase: 0,
    minNumbers: 0,
    minSymbols: 0 
  })) {
    return 'Please choose a stronger password';
  }
  return null;
};

const validateOTP = (otp) => {
  if (!otp || !validator.isNumeric(otp) || otp.length !== 6) {
    return 'Please provide a valid 6-digit OTP';
  }
  return null;
};

// Helper to clean up unverified users
const cleanupUnverifiedUser = async (email) => {
  try {
    await User.deleteOne({ email: email.toLowerCase(), isVerified: false });
  } catch (error) {
    console.error('Cleanup error:', error);
  }
};

// Sanitize user input
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return validator.escape(validator.trim(input));
  }
  return input;
};

// Enhanced response formatter
const formatResponse = (success, message, data = null, statusCode = 200) => {
  const response = {
    success,
    message,
    timestamp: new Date().toISOString(),
    ...(data && { data })
  };
  return { statusCode, response };
};

// Sign up controller - IMPROVED VERSION
export const signUp = async (req, res) => {
  try {
    let { name, email, password } = req.body;

    // Sanitize inputs
    name = sanitizeInput(name);
    email = sanitizeInput(email);
    password = sanitizeInput(password);

    // Validate inputs
    const nameError = validateName(name);
    const emailError = validateEmail(email);
    const passwordError = validatePassword(password);

    const errors = [nameError, emailError, passwordError].filter(error => error !== null);

    if (errors.length > 0) {
      const { statusCode, response } = formatResponse(false, errors[0], null, 400);
      return res.status(statusCode).json(response);
    }

    const userEmail = email.toLowerCase();

    // Check if email already exists and is verified
    const existingVerifiedUser = await User.findOne({ 
      email: userEmail, 
      isVerified: true 
    });

    if (existingVerifiedUser) {
      const { statusCode, response } = formatResponse(false, 'An account with this email already exists. Please sign in instead.', null, 409);
      return res.status(statusCode).json(response);
    }

    // Check if there's an unverified user with this email
    const existingUnverifiedUser = await User.findOne({ 
      email: userEmail, 
      isVerified: false 
    });

    let user;
    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationOTP = generateOTP();

    if (existingUnverifiedUser) {
      // Update existing unverified user
      user = await User.findOneAndUpdate(
        { email: userEmail, isVerified: false },
        { 
          name: name.trim(),
          password: hashedPassword,
          verificationToken: verificationOTP,
          verificationExpires: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
          updatedAt: new Date()
        },
        { new: true, runValidators: true }
      );
    } else {
      // Create new user
      user = new User({
        name: name.trim(),
        email: userEmail,
        password: hashedPassword,
        verificationToken: verificationOTP,
        verificationExpires: new Date(Date.now() + 60 * 60 * 1000),
      });
      await user.save();
    }

    // Send verification email
    const emailSent = await sendVerificationEmail(userEmail, verificationOTP, name.trim());

    if (!emailSent) {
      await cleanupUnverifiedUser(userEmail);
      const { statusCode, response } = formatResponse(false, 'We encountered an issue sending the verification email. Please try again.', null, 500);
      return res.status(statusCode).json(response);
    }

    // Log successful signup attempt
    console.log(`Signup attempt - Email: ${userEmail}, UserId: ${user._id}, Timestamp: ${new Date().toISOString()}`);

    const { statusCode, response } = formatResponse(
      true, 
      'Verification code sent to your email. Please check your inbox to complete registration.',
      { userId: user._id }
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Signup error:', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    
    // Handle duplicate key error for verified emails
    if (error.code === 11000) {
      const { statusCode, response } = formatResponse(false, 'An account with this email already exists.', null, 409);
      return res.status(statusCode).json(response);
    }
    
    // Handle validation errors
    if (error.name === 'ValidationError') {
      const { statusCode, response } = formatResponse(false, 'Invalid input data. Please check your information.', null, 400);
      return res.status(statusCode).json(response);
    }
    
    const { statusCode, response } = formatResponse(false, 'We encountered an issue creating your account. Please try again.', null, 500);
    res.status(statusCode).json(response);
  }
};

// Verify OTP controller - IMPROVED VERSION
export const verifyOTP = async (req, res) => {
  try {
    let { email, otp } = req.body;

    // Sanitize inputs
    email = sanitizeInput(email);
    otp = sanitizeInput(otp);

    // Validate inputs
    const emailError = validateEmail(email);
    const otpError = validateOTP(otp);

    const errors = [emailError, otpError].filter(error => error !== null);

    if (errors.length > 0) {
      const { statusCode, response } = formatResponse(false, errors[0], null, 400);
      return res.status(statusCode).json(response);
    }

    const userEmail = email.toLowerCase();

    const user = await User.findOne({
      email: userEmail,
      verificationToken: otp,
      verificationExpires: { $gt: new Date() }
    });

    if (!user) {
      console.log(`Failed OTP verification attempt - Email: ${userEmail}, OTP: ${otp}`);
      const { statusCode, response } = formatResponse(false, 'The verification code is invalid or has expired. Please request a new one.', null, 400);
      return res.status(statusCode).json(response);
    }

    // Mark user as verified and clear verification token
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    user.verifiedAt = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        email: user.email, 
        name: user.name 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    // Log successful verification
    console.log(`Successful email verification - Email: ${userEmail}, UserId: ${user._id}`);

    const { statusCode, response } = formatResponse(
      true,
      'Email verified successfully! Welcome to our platform.',
      {
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          isVerified: user.isVerified,
          verifiedAt: user.verifiedAt
        }
      }
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('OTP verification error:', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    
    const { statusCode, response } = formatResponse(false, 'We encountered an issue verifying your code. Please try again.', null, 500);
    res.status(statusCode).json(response);
  }
};

// Resend OTP controller - IMPROVED VERSION
export const resendOTP = async (req, res) => {
  try {
    let { email } = req.body;

    // Sanitize input
    email = sanitizeInput(email);

    // Validate input
    const emailError = validateEmail(email);
    if (emailError) {
      const { statusCode, response } = formatResponse(false, emailError, null, 400);
      return res.status(statusCode).json(response);
    }

    const userEmail = email.toLowerCase();

    const user = await User.findOne({ 
      email: userEmail, 
      isVerified: false 
    });

    if (!user) {
      console.log(`Resend OTP attempt for non-existent/unverified user - Email: ${userEmail}`);
      const { statusCode, response } = formatResponse(false, 'No pending verification found for this email. Please sign up again.', null, 404);
      return res.status(statusCode).json(response);
    }

    // Check if we should wait before resending
    const timeSinceLastOTP = new Date() - user.verificationExpires;
    const minResendWaitTime = 1 * 60 * 1000; // 1 minute

    if (timeSinceLastOTP < minResendWaitTime && timeSinceLastOTP > 0) {
      const waitTime = Math.ceil((minResendWaitTime - timeSinceLastOTP) / 1000);
      const { statusCode, response } = formatResponse(false, `Please wait ${waitTime} seconds before requesting a new code.`, null, 429);
      return res.status(statusCode).json(response);
    }

    const verificationOTP = generateOTP();
    
    user.verificationToken = verificationOTP;
    user.verificationExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();

    const emailSent = await sendVerificationEmail(userEmail, verificationOTP, user.name);

    if (!emailSent) {
      const { statusCode, response } = formatResponse(false, 'We encountered an issue sending the verification code. Please try again.', null, 500);
      return res.status(statusCode).json(response);
    }

    console.log(`OTP resent - Email: ${userEmail}, UserId: ${user._id}`);

    const { statusCode, response } = formatResponse(true, 'New verification code sent to your email.');
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Resend OTP error:', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    
    const { statusCode, response } = formatResponse(false, 'We encountered an issue resending the code. Please try again.', null, 500);
    res.status(statusCode).json(response);
  }
};

// Sign in controller - IMPROVED VERSION
export const signIn = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate inputs
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user by email (only verified users)
    const user = await User.findOne({ 
      email: email.toLowerCase(), 
      isVerified: true 
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials or email not verified'
      });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate JWT token (access token)
    const token = jwt.sign(
      { 
        userId: user._id, 
        email: user.email, 
        name: user.name 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    // Generate refresh token
    const refreshToken = jwt.sign(
      { 
        userId: user._id 
      },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN }
    );

    // Save refresh token to user
    user.refreshToken = refreshToken;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Sign in successful',
      token,
      refreshToken, // ADD THIS LINE
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isVerified: user.isVerified
      }
    });

  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during sign in'
    });
  }
};

// Get current user profile - IMPROVED VERSION
export const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password -verificationToken -verificationExpires -resetPasswordToken -resetPasswordExpires');
    
    if (!user) {
      const { statusCode, response } = formatResponse(false, 'User account not found.', null, 404);
      return res.status(statusCode).json(response);
    }

    const { statusCode, response } = formatResponse(
      true,
      'Profile retrieved successfully.',
      {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          isVerified: user.isVerified,
          createdAt: user.createdAt,
          verifiedAt: user.verifiedAt,
          lastLoginAt: user.lastLoginAt
        }
      }
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Get profile error:', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    
    const { statusCode, response } = formatResponse(false, 'We encountered an issue retrieving your profile.', null, 500);
    res.status(statusCode).json(response);
  }
};

// Forgot password - IMPROVED VERSION
export const forgotPassword = async (req, res) => {
  try {
    let { email } = req.body;

    // Sanitize input
    email = sanitizeInput(email);

    // Validate input
    const emailError = validateEmail(email);
    if (emailError) {
      const { statusCode, response } = formatResponse(false, emailError, null, 400);
      return res.status(statusCode).json(response);
    }

    const userEmail = email.toLowerCase();

    // Additional check: Prevent multiple reset requests for same email within 2 minutes
    const recentResetAttempt = await User.findOne({
      email: userEmail,
      resetPasswordExpires: { $gt: new Date(Date.now() - 2 * 60 * 1000) } // Last 2 minutes
    });

    if (recentResetAttempt && recentResetAttempt.resetPasswordToken) {
      const { statusCode, response } = formatResponse(false, 'A reset code was already sent recently. Please check your email or wait 2 minutes.', null, 429);
      return res.status(statusCode).json(response);
    }

    // Find verified user
    const user = await User.findOne({ 
      email: userEmail, 
      isVerified: true 
    });

    // Always return success for security (even if user doesn't exist)
    if (!user) {
      console.log(`Password reset request for non-existent/verified user - Email: ${userEmail}`);
      const { statusCode, response } = formatResponse(true, 'If an account exists with this email, a password reset code has been sent.');
      return res.status(statusCode).json(response);
    }

    // Generate OTP
    const resetOTP = generateOTP();
    
    // Update user with reset token
    await User.updateOne(
      { _id: user._id },
      {
        resetPasswordToken: resetOTP,
        resetPasswordExpires: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes expiry
        resetPasswordAttempts: 0
      }
    );

    // Send email
    const emailSent = await sendPasswordResetEmail(
      userEmail, 
      resetOTP, 
      user.name || 'User'
    );

    if (!emailSent) {
      // Clear reset token if email failed
      await User.updateOne(
        { _id: user._id },
        {
          $unset: {
            resetPasswordToken: "",
            resetPasswordExpires: ""
          }
        }
      );

      const { statusCode, response } = formatResponse(false, 'We encountered an issue sending the reset code. Please try again.', null, 500);
      return res.status(statusCode).json(response);
    }

    console.log(`Password reset OTP sent - Email: ${userEmail}, UserId: ${user._id}`);

    const { statusCode, response } = formatResponse(true, 'If an account exists with this email, a password reset code has been sent.');
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Password reset error:', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    
    const { statusCode, response } = formatResponse(false, 'We encountered an issue processing your request. Please try again.', null, 500);
    res.status(statusCode).json(response);
  }
};

// Verify reset OTP - IMPROVED VERSION
export const verifyResetOTP = async (req, res) => {
  try {
    let { email, otp } = req.body;

    // Sanitize inputs
    email = sanitizeInput(email);
    otp = sanitizeInput(otp);

    // Validate inputs
    const emailError = validateEmail(email);
    const otpError = validateOTP(otp);

    const errors = [emailError, otpError].filter(error => error !== null);

    if (errors.length > 0) {
      const { statusCode, response } = formatResponse(false, errors[0], null, 400);
      return res.status(statusCode).json(response);
    }

    const userEmail = email.toLowerCase();

    // Find user with valid reset token - Ensure user is verified
    const user = await User.findOne({
      email: userEmail,
      resetPasswordToken: otp,
      resetPasswordExpires: { $gt: new Date() },
      isVerified: true // CRITICAL: Only allow verified users
    });

    if (!user) {
      console.log(`Invalid reset OTP attempt - Email: ${userEmail}, OTP: ${otp}`);
      const { statusCode, response } = formatResponse(false, 'The reset code is invalid or has expired. Please request a new one.', null, 400);
      return res.status(statusCode).json(response);
    }

    // Generate a verification token for the reset process
    const resetVerificationToken = jwt.sign(
      { 
        userId: user._id, 
        email: user.email,
        purpose: 'password_reset'
      },
      process.env.JWT_SECRET,
      { expiresIn: '15m' } // Short-lived token for security
    );

    console.log(`Reset OTP verified successfully - Email: ${userEmail}, UserId: ${user._id}`);

    const { statusCode, response } = formatResponse(
      true,
      'Code verified successfully. You can now reset your password.',
      { resetToken: resetVerificationToken }
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Verify reset OTP error:', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    
    const { statusCode, response } = formatResponse(false, 'We encountered an issue verifying your code. Please try again.', null, 500);
    res.status(statusCode).json(response);
  }
};

// Reset password - IMPROVED VERSION
export const resetPassword = async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    // Validate inputs
    if (!resetToken || !newPassword) {
      const { statusCode, response } = formatResponse(false, 'Reset token and new password are required.', null, 400);
      return res.status(statusCode).json(response);
    }

    const passwordError = validatePassword(newPassword);
    if (passwordError) {
      const { statusCode, response } = formatResponse(false, passwordError, null, 400);
      return res.status(statusCode).json(response);
    }

    // Verify reset token
    let decoded;
    try {
      decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
      
      // Check if token is for password reset
      if (decoded.purpose !== 'password_reset') {
        const { statusCode, response } = formatResponse(false, 'Invalid reset token.', null, 400);
        return res.status(statusCode).json(response);
      }
    } catch (error) {
      const { statusCode, response } = formatResponse(false, 'The reset token has expired or is invalid. Please start the reset process again.', null, 400);
      return res.status(statusCode).json(response);
    }

    // Find user - Ensure user is verified
    const user = await User.findOne({
      _id: decoded.userId,
      email: decoded.email,
      isVerified: true // CRITICAL: Only reset for verified users
    });

    if (!user) {
      const { statusCode, response } = formatResponse(false, 'User account not found or not verified.', null, 400);
      return res.status(statusCode).json(response);
    }

    // Check if old and new password are the same
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      const { statusCode, response } = formatResponse(false, 'New password cannot be the same as your current password.', null, 400);
      return res.status(statusCode).json(response);
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password and clear reset tokens
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    user.passwordChangedAt = new Date();
    await user.save();

    console.log(`Password reset successfully - Email: ${user.email}, UserId: ${user._id}`);

    const { statusCode, response } = formatResponse(true, 'Password reset successfully! You can now sign in with your new password.');
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Reset password error:', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    
    const { statusCode, response } = formatResponse(false, 'We encountered an issue resetting your password. Please try again.', null, 500);
    res.status(statusCode).json(response);
  }
};
export const refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token required'
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Find user with this refresh token
    const user = await User.findOne({ 
      _id: decoded.userId, 
      refreshToken: refreshToken 
    });

    if (!user) {
      return res.status(403).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    // Generate new access token
    const newAccessToken = jwt.sign(
      { 
        userId: user._id, 
        email: user.email, 
        name: user.name 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      token: newAccessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isVerified: user.isVerified
      }
    });

  } catch (error) {
    console.error('Refresh token error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({
        success: false,
        message: 'Refresh token expired. Please sign in again.'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Internal server error during token refresh'
    });
  }
};

// Logout Controller
export const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token required'
      });
    }

    // Find user and remove refresh token
    await User.findOneAndUpdate(
      { refreshToken: refreshToken },
      { $unset: { refreshToken: 1 } }
    );

    res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during logout'
    });
  }
};

// Logout All Devices Controller
export const logoutAll = async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID required'
      });
    }

    // Remove refresh token from all users with this ID
    await User.findByIdAndUpdate(
      userId,
      { $unset: { refreshToken: 1 } }
    );

    res.status(200).json({
      success: true,
      message: 'Logged out from all devices successfully'
    });

  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during logout'
    });
  }
};