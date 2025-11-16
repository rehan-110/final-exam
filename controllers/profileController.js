import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import validator from 'validator';
import { generateOTP, sendProfileUpdateEmail } from '../utils/emailService.js';

// Helper function to format response
const formatResponse = (success, message, data = null, statusCode = 200) => {
  return {
    statusCode,
    response: {
      success,
      message,
      timestamp: new Date().toISOString(),
      ...(data && { data })
    }
  };
};

// Validation functions
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
  return null;
};

// Sanitize input
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return validator.escape(validator.trim(input));
  }
  return input;
};

// 6.3.1 Get Profile API
export const getProfile = async (req, res) => {
  try {
    const userId = req.userId;

    const user = await User.findById(userId).select('-password -verificationToken -verificationExpires -resetPasswordToken -resetPasswordExpires -refreshToken -__v');

    if (!user) {
      const { statusCode, response } = formatResponse(false, 'User not found', null, 404);
      return res.status(statusCode).json(response);
    }

    const userProfile = {
      id: user._id,
      name: user.name,
      email: user.email,
      isVerified: user.isVerified,
      role: user.role,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };

    console.log(`✅ Profile retrieved - UserId: ${userId}`);

    const { statusCode, response } = formatResponse(
      true,
      'Profile retrieved successfully',
      { user: userProfile }
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('❌ Get profile error:', {
      error: error.message,
      stack: error.stack,
      userId: req.userId,
      timestamp: new Date().toISOString()
    });

    const { statusCode, response } = formatResponse(false, 'Failed to retrieve profile', null, 500);
    res.status(statusCode).json(response);
  }
};

// 6.3.2 Update Profile API
export const updateProfile = async (req, res) => {
  try {
    const userId = req.userId;
    const { name, email, currentPassword, newPassword } = req.body;

    console.log(`🔄 Profile update request - UserId: ${userId}`);
    console.log('📝 Update data:', { 
      name: name ? `${name.substring(0, 10)}...` : 'Not provided', 
      email: email ? `${email.substring(0, 10)}...` : 'Not provided', 
      hasCurrentPassword: !!currentPassword, 
      hasNewPassword: !!newPassword 
    });

    // Find user
    const user = await User.findById(userId);
    if (!user) {
      console.log('❌ User not found for profile update');
      const { statusCode, response } = formatResponse(false, 'User not found', null, 404);
      return res.status(statusCode).json(response);
    }

    // Prepare update data
    const updateData = {};
    const validationErrors = [];
    let requiresEmailVerification = false;
    let newEmail = null;

    // Validate and update name
    if (name) {
      const nameError = validateName(name);
      if (nameError) {
        console.log('❌ Name validation error:', nameError);
        validationErrors.push(nameError);
      } else {
        updateData.name = sanitizeInput(name);
        console.log('✅ Name update approved');
      }
    }

    // Validate and update email
    if (email && email !== user.email) {
      console.log('📧 Email change requested:', { from: user.email, to: email });
      
      const emailError = validateEmail(email);
      if (emailError) {
        console.log('❌ Email validation error:', emailError);
        validationErrors.push(emailError);
      } else {
        // Check if email already exists
        const existingUser = await User.findOne({ 
          email: email.toLowerCase(), 
          _id: { $ne: userId } 
        });
        
        if (existingUser) {
          console.log('❌ Email already exists for another user');
          validationErrors.push('Email is already taken');
        } else {
          newEmail = sanitizeInput(email).toLowerCase();
          requiresEmailVerification = true;
          
          // Generate OTP for email verification
          const verificationOTP = generateOTP();
          console.log('🔐 Generated OTP for email verification:', verificationOTP);
          
          updateData.email = newEmail;
          updateData.isVerified = false;
          updateData.verificationToken = verificationOTP;
          updateData.verificationExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
          
          console.log('✅ Email update approved, verification required');
        }
      }
    }

    // Handle password change
    if (newPassword) {
      if (!currentPassword) {
        console.log('❌ Current password required for password change');
        validationErrors.push('Current password is required to set new password');
      } else {
        // Verify current password
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isCurrentPasswordValid) {
          console.log('❌ Current password is incorrect');
          validationErrors.push('Current password is incorrect');
        } else {
          const passwordError = validatePassword(newPassword);
          if (passwordError) {
            console.log('❌ New password validation error:', passwordError);
            validationErrors.push(passwordError);
          } else {
            // Check if new password is same as current
            const isSamePassword = await bcrypt.compare(newPassword, user.password);
            if (isSamePassword) {
              console.log('❌ New password cannot be same as current');
              validationErrors.push('New password cannot be the same as current password');
            } else {
              updateData.password = await bcrypt.hash(newPassword, 12);
              console.log('✅ Password update approved');
            }
          }
        }
      }
    }

    // Return validation errors if any
    if (validationErrors.length > 0) {
      console.log('❌ Validation errors:', validationErrors);
      const { statusCode, response } = formatResponse(false, validationErrors[0], null, 400);
      return res.status(statusCode).json(response);
    }

    // Check if there are any updates
    if (Object.keys(updateData).length === 0) {
      console.log('❌ No changes provided for update');
      const { statusCode, response } = formatResponse(false, 'No changes provided for update', null, 400);
      return res.status(statusCode).json(response);
    }

    // If email is being changed, send verification OTP
    if (requiresEmailVerification && newEmail) {
      console.log(`📧 Sending profile update verification email to: ${newEmail}`);
      console.log(`🔐 OTP: ${updateData.verificationToken}`);
      
      // Use profile update email function
      const emailSent = await sendProfileUpdateEmail(newEmail, updateData.verificationToken, updateData.name || user.name);
      
      if (!emailSent) {
        console.error('❌ Failed to send profile update verification email to:', newEmail);
        const { statusCode, response } = formatResponse(false, 'Failed to send verification email. Please try again.', null, 500);
        return res.status(statusCode).json(response);
      }
      
      console.log('✅ Profile update verification email sent successfully to:', newEmail);
    }

    // Update user
    updateData.updatedAt = new Date();
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    ).select('-password -verificationToken -verificationExpires -resetPasswordToken -resetPasswordExpires -refreshToken -__v');

    const userProfile = {
      id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      isVerified: updatedUser.isVerified,
      role: updatedUser.role,
      lastLoginAt: updatedUser.lastLoginAt,
      createdAt: updatedUser.createdAt,
      updatedAt: updatedUser.updatedAt
    };

    console.log(`✅ Profile updated successfully - UserId: ${userId}`);

    let message = 'Profile updated successfully';
    if (requiresEmailVerification) {
      message = 'Profile updated successfully. Please check your email for verification code.';
      console.log(`📧 Email verification required for: ${newEmail}`);
    }

    const { statusCode, response } = formatResponse(
      true,
      message,
      { 
        user: userProfile,
        requiresEmailVerification: requiresEmailVerification
      }
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('❌ Update profile error:', {
      error: error.message,
      stack: error.stack,
      userId: req.userId,
      timestamp: new Date().toISOString()
    });

    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      const { statusCode, response } = formatResponse(false, 'Validation error: ' + errors.join(', '), null, 400);
      return res.status(statusCode).json(response);
    }

    if (error.code === 11000) {
      const { statusCode, response } = formatResponse(false, 'Email already exists', null, 409);
      return res.status(statusCode).json(response);
    }

    const { statusCode, response } = formatResponse(false, 'Failed to update profile', null, 500);
    res.status(statusCode).json(response);
  }
};

// Verify updated email
export const verifyUpdatedEmail = async (req, res) => {
  try {
    const userId = req.userId;
    const { otp } = req.body;

    console.log(`🔐 Email verification attempt - UserId: ${userId}, OTP: ${otp}`);

    if (!otp) {
      console.log('❌ OTP is required for verification');
      const { statusCode, response } = formatResponse(false, 'OTP is required', null, 400);
      return res.status(statusCode).json(response);
    }

    const user = await User.findOne({
      _id: userId,
      verificationToken: otp,
      verificationExpires: { $gt: new Date() }
    });

    if (!user) {
      console.log('❌ Invalid or expired OTP for user:', userId);
      const { statusCode, response } = formatResponse(false, 'Invalid or expired verification code', null, 400);
      return res.status(statusCode).json(response);
    }

    // Mark user as verified and clear verification token
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    user.verifiedAt = new Date();
    await user.save();

    const userProfile = {
      id: user._id,
      name: user.name,
      email: user.email,
      isVerified: user.isVerified,
      role: user.role,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };

    console.log(`✅ Email verified successfully - UserId: ${userId}, Email: ${user.email}`);

    const { statusCode, response } = formatResponse(
      true,
      'Email verified successfully! Your profile is now fully updated.',
      { user: userProfile }
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('❌ Verify updated email error:', {
      error: error.message,
      stack: error.stack,
      userId: req.userId,
      timestamp: new Date().toISOString()
    });

    const { statusCode, response } = formatResponse(false, 'Failed to verify email', null, 500);
    res.status(statusCode).json(response);
  }
};

// Resend verification email for updated email
export const resendEmailVerification = async (req, res) => {
  try {
    const userId = req.userId;

    console.log(`📧 Resend verification request - UserId: ${userId}`);

    const user = await User.findById(userId);
    if (!user) {
      console.log('❌ User not found for resend verification');
      const { statusCode, response } = formatResponse(false, 'User not found', null, 404);
      return res.status(statusCode).json(response);
    }

    if (user.isVerified) {
      console.log('❌ Email is already verified for user:', userId);
      const { statusCode, response } = formatResponse(false, 'Email is already verified', null, 400);
      return res.status(statusCode).json(response);
    }

    // Check if user has a pending verification token
    if (!user.verificationToken || user.verificationExpires < new Date()) {
      // Generate new OTP if none exists or expired
      const verificationOTP = generateOTP();
      user.verificationToken = verificationOTP;
      user.verificationExpires = new Date(Date.now() + 60 * 60 * 1000);
      console.log('🔐 Generated new OTP for resend:', verificationOTP);
    } else {
      console.log('🔐 Using existing OTP for resend:', user.verificationToken);
    }

    await user.save();

    console.log(`📧 Sending profile update verification email to: ${user.email}`);

    // Send profile update verification email
    const emailSent = await sendProfileUpdateEmail(user.email, user.verificationToken, user.name);

    if (!emailSent) {
      console.error('❌ Failed to send profile update verification email to:', user.email);
      const { statusCode, response } = formatResponse(false, 'Failed to send verification email. Please try again.', null, 500);
      return res.status(statusCode).json(response);
    }

    console.log('✅ Profile update verification email resent successfully to:', user.email);

    const { statusCode, response } = formatResponse(
      true,
      'Verification email sent successfully. Please check your inbox.'
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('❌ Resend verification email error:', {
      error: error.message,
      stack: error.stack,
      userId: req.userId,
      timestamp: new Date().toISOString()
    });

    const { statusCode, response } = formatResponse(false, 'Failed to resend verification email', null, 500);
    res.status(statusCode).json(response);
  }
};