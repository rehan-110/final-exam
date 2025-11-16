import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

// Email configuration with fallbacks
const emailConfig = {
  service: process.env.EMAIL_SERVICE || 'gmail',
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.EMAIL_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  // Connection timeout
  connectionTimeout: 30000,
  // Socket timeout
  socketTimeout: 30000,
};

// Create transporter with better configuration
const transporter = nodemailer.createTransport(emailConfig);

// Verify transporter configuration with retry
const verifyTransporter = async (retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      await transporter.verify();
      console.log('✅ Email server is ready to take our messages');
      return true;
    } catch (error) {
      console.error(`❌ Email transporter verification attempt ${i + 1} failed:`, error.message);
      if (i === retries - 1) {
        console.error('🚨 Email server configuration failed after multiple attempts');
        return false;
      }
      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
};

// Initialize email service
verifyTransporter();

// Email template system
const emailTemplates = {
  verification: {
    subject: 'Verify Your Email Address - ExamVerified',
    generateHTML: (data) => `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f6f9fc; }
        .container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center; color: white; }
        .header h1 { font-size: 28px; font-weight: 600; margin-bottom: 10px; }
        .header p { font-size: 16px; opacity: 0.9; }
        .content { padding: 40px 30px; }
        .greeting { font-size: 18px; margin-bottom: 20px; color: #444; }
        .otp-container { background: #f8f9fa; border: 2px dashed #dee2e6; border-radius: 8px; padding: 25px; text-align: center; margin: 30px 0; }
        .otp-code { font-size: 42px; font-weight: bold; color: #495057; letter-spacing: 8px; font-family: 'Courier New', monospace; }
        .instructions { background: #e7f3ff; border-left: 4px solid #1890ff; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .footer { background: #f8f9fa; padding: 25px 30px; text-align: center; color: #6c757d; font-size: 14px; border-top: 1px solid #e9ecef; }
        .warning { color: #dc3545; font-size: 12px; margin-top: 10px; }
        .support { margin-top: 15px; color: #495057; }
        @media (max-width: 600px) {
            .container { margin: 10px; }
            .header { padding: 30px 20px; }
            .content { padding: 30px 20px; }
            .otp-code { font-size: 32px; letter-spacing: 6px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Verify Your Email</h1>
            <p>Complete your registration with ExamVerified</p>
        </div>
        <div class="content">
            <p class="greeting">Hello <strong>${data.name}</strong>,</p>
            <p>Thank you for choosing ExamVerified! To complete your registration and start using our platform, please use the verification code below:</p>
            
            <div class="otp-container">
                <div class="otp-code">${data.otp}</div>
            </div>
            
            <div class="instructions">
                <strong>📋 Instructions:</strong>
                <p>Enter this code in the verification page to activate your account. This code will expire in <strong>1 hour</strong>.</p>
            </div>
            
            <p>If you didn't create an account with ExamVerified, please ignore this email or contact our support team if you have concerns.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 ExamVerified. All rights reserved.</p>
            <p class="warning">⚠️ For your security, never share this code with anyone.</p>
            <p class="support">Need help? Contact our support team at <a href="mailto:support@examverified.com">support@examverified.com</a></p>
        </div>
    </div>
</body>
</html>
    `
  },
  
  profileUpdate: {
    subject: 'Verify Your Updated Email - ExamVerified',
    generateHTML: (data) => `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification - Profile Update</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f6f9fc; }
        .container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .header { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); padding: 40px 30px; text-align: center; color: white; }
        .header h1 { font-size: 28px; font-weight: 600; margin-bottom: 10px; }
        .header p { font-size: 16px; opacity: 0.9; }
        .content { padding: 40px 30px; }
        .greeting { font-size: 18px; margin-bottom: 20px; color: #444; }
        .otp-container { background: #fff5f5; border: 2px dashed #ff6b6b; border-radius: 8px; padding: 25px; text-align: center; margin: 30px 0; }
        .otp-code { font-size: 42px; font-weight: bold; color: #c44569; letter-spacing: 8px; font-family: 'Courier New', monospace; }
        .instructions { background: #ffeaa7; border-left: 4px solid #fdcb6e; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .security-note { background: #d1ecf1; border-left: 4px solid #17a2b8; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .footer { background: #f8f9fa; padding: 25px 30px; text-align: center; color: #6c757d; font-size: 14px; border-top: 1px solid #e9ecef; }
        .warning { color: #dc3545; font-size: 12px; margin-top: 10px; }
        .support { margin-top: 15px; color: #495057; }
        @media (max-width: 600px) {
            .container { margin: 10px; }
            .header { padding: 30px 20px; }
            .content { padding: 30px 20px; }
            .otp-code { font-size: 32px; letter-spacing: 6px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📧 Email Updated</h1>
            <p>Verify your new email address</p>
        </div>
        <div class="content">
            <p class="greeting">Hello <strong>${data.name}</strong>,</p>
            <p>You've successfully updated your email address in ExamVerified. To complete this change and verify your new email, please use the verification code below:</p>
            
            <div class="otp-container">
                <div class="otp-code">${data.otp}</div>
            </div>
            
            <div class="instructions">
                <strong>🚀 Action Required:</strong>
                <p>Enter this code in your profile settings to verify your new email address. This code will expire in <strong>1 hour</strong>.</p>
            </div>
            
            <div class="security-note">
                <strong>🔒 Security Notice:</strong>
                <p>If you didn't request this email change, please contact our support team immediately to secure your account.</p>
            </div>
            
            <p>Once verified, all future communications will be sent to this email address.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 ExamVerified. All rights reserved.</p>
            <p class="warning">⚠️ Never share this code with anyone. ExamVerified will never ask for your verification codes.</p>
            <p class="support">Questions? Contact <a href="mailto:support@examverified.com">support@examverified.com</a></p>
        </div>
    </div>
</body>
</html>
    `
  },
  
  passwordReset: {
    subject: 'Password Reset Request - ExamVerified',
    generateHTML: (data) => `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f6f9fc; }
        .container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .header { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); padding: 40px 30px; text-align: center; color: white; }
        .header h1 { font-size: 28px; font-weight: 600; margin-bottom: 10px; }
        .header p { font-size: 16px; opacity: 0.9; }
        .content { padding: 40px 30px; }
        .greeting { font-size: 18px; margin-bottom: 20px; color: #444; }
        .otp-container { background: #fff5f5; border: 2px dashed #ff6b6b; border-radius: 8px; padding: 25px; text-align: center; margin: 30px 0; }
        .otp-code { font-size: 42px; font-weight: bold; color: #c44569; letter-spacing: 8px; font-family: 'Courier New', monospace; }
        .instructions { background: #ffeaa7; border-left: 4px solid #fdcb6e; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .security-note { background: #d1ecf1; border-left: 4px solid #17a2b8; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .footer { background: #f8f9fa; padding: 25px 30px; text-align: center; color: #6c757d; font-size: 14px; border-top: 1px solid #e9ecef; }
        .warning { color: #dc3545; font-size: 12px; margin-top: 10px; }
        .support { margin-top: 15px; color: #495057; }
        @media (max-width: 600px) {
            .container { margin: 10px; }
            .header { padding: 30px 20px; }
            .content { padding: 30px 20px; }
            .otp-code { font-size: 32px; letter-spacing: 6px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Reset Your Password</h1>
            <p>Secure your ExamVerified account</p>
        </div>
        <div class="content">
            <p class="greeting">Hello <strong>${data.name}</strong>,</p>
            <p>We received a request to reset your password for your ExamVerified account. Use the verification code below to proceed:</p>
            
            <div class="otp-container">
                <div class="otp-code">${data.otp}</div>
            </div>
            
            <div class="instructions">
                <strong>🚀 Quick Action Required:</strong>
                <p>Enter this code in the password reset page within <strong>30 minutes</strong> to set a new password for your account.</p>
            </div>
            
            <div class="security-note">
                <strong>🔒 Security Notice:</strong>
                <p>If you didn't request this password reset, please ignore this email. Your account remains secure, and no changes have been made.</p>
            </div>
            
            <p>For security reasons, this code is valid for a limited time only and can be used once.</p>
        </div>
        <div class="footer">
            <p>&copy; 2024 ExamVerified. All rights reserved.</p>
            <p class="warning">⚠️ Never share this code with anyone. ExamVerified will never ask for your password or verification codes.</p>
            <p class="support">Questions? Contact <a href="mailto:support@examverified.com">support@examverified.com</a></p>
        </div>
    </div>
</body>
</html>
    `
  }
};

// Generate OTP with better randomness
export const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Enhanced email sending with retry logic
const sendEmailWithRetry = async (emailOptions, retries = 3) => {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const info = await transporter.sendMail(emailOptions);
      console.log(`✅ Email sent successfully (Attempt ${attempt}):`, {
        messageId: info.messageId,
        to: emailOptions.to,
        subject: emailOptions.subject,
        timestamp: new Date().toISOString()
      });
      return info;
    } catch (error) {
      console.error(`❌ Email send attempt ${attempt} failed:`, {
        error: error.message,
        to: emailOptions.to,
        subject: emailOptions.subject
      });
      
      if (attempt === retries) {
        throw new Error(`Failed to send email after ${retries} attempts: ${error.message}`);
      }
      
      // Wait before retry (exponential backoff)
      await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
    }
  }
};

// Template-based email sender
const sendTemplatedEmail = async (templateName, email, data) => {
  const template = emailTemplates[templateName];
  
  if (!template) {
    throw new Error(`Template '${templateName}' not found`);
  }

  const mailOptions = {
    from: {
      name: process.env.EMAIL_FROM_NAME || 'ExamVerified',
      address: process.env.EMAIL_USER
    },
    to: email,
    subject: template.subject,
    html: template.generateHTML(data),
    // Add headers for better email deliverability
    headers: {
      'X-Priority': '1',
      'X-MSMail-Priority': 'High',
      'Importance': 'high'
    }
  };

  return await sendEmailWithRetry(mailOptions);
};

// Send verification email - FIXED VERSION
export const sendVerificationEmail = async (email, otp, name = 'User') => {
  try {
    console.log(`📧 Sending verification email to: ${email}`);
    console.log(`🔐 OTP: ${otp}, Name: ${name}`);

    await sendTemplatedEmail('verification', email, {
      name: name,
      otp: otp,
      expiryTime: '1 hour',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@examverified.com'
    });
    
    console.log(`✅ Verification email sent successfully to: ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Error sending verification email:', {
      error: error.message,
      email: email,
      timestamp: new Date().toISOString()
    });
    return false;
  }
};

// Send profile update verification email - NEW FUNCTION
export const sendProfileUpdateEmail = async (email, otp, name = 'User') => {
  try {
    console.log(`📧 Sending profile update verification email to: ${email}`);
    console.log(`🔐 OTP: ${otp}, Name: ${name}`);

    await sendTemplatedEmail('profileUpdate', email, {
      name: name,
      otp: otp,
      expiryTime: '1 hour',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@examverified.com'
    });
    
    console.log(`✅ Profile update verification email sent successfully to: ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Error sending profile update verification email:', {
      error: error.message,
      email: email,
      timestamp: new Date().toISOString()
    });
    return false;
  }
};

// Send password reset email
export const sendPasswordResetEmail = async (email, otp, name = 'User') => {
  try {
    console.log(`📧 Sending password reset email to: ${email}`);
    console.log(`🔐 OTP: ${otp}, Name: ${name}`);

    await sendTemplatedEmail('passwordReset', email, {
      name: name,
      otp: otp,
      expiryTime: '30 minutes',
      supportEmail: process.env.SUPPORT_EMAIL || 'support@examverified.com'
    });
    
    console.log(`✅ Password reset email sent successfully to: ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Error sending password reset email:', {
      error: error.message,
      email: email,
      timestamp: new Date().toISOString()
    });
    return false;
  }
};

// Test email function
export const testEmailService = async (testEmail) => {
  try {
    const testOTP = generateOTP();
    const result = await sendVerificationEmail(testEmail, testOTP, 'Test User');
    
    if (result) {
      console.log('✅ Email service test passed');
      return { success: true, message: 'Test email sent successfully' };
    } else {
      console.log('❌ Email service test failed');
      return { success: false, message: 'Failed to send test email' };
    }
  } catch (error) {
    console.error('❌ Email service test error:', error);
    return { success: false, message: error.message };
  }
};

export default transporter;