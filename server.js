import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import connectDB from './config/database.js';
import authRoutes from './routes/authRoutes.js';
import appRoutes from './routes/appRoutes.js';
import { globalLimiter } from './middleware/rateLimitMiddleware.js';
import mongoose from 'mongoose';
import appointmentRoutes from './routes/appointmentRoutes.js';
import profileRoutes from './routes/profileRoutes.js';
import recordRoutes from './routes/recordRoutes.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// Load environment variables
dotenv.config({ debug: false });

const app = express();

// Connect to Database
connectDB();

// Basic Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Rate Limiting (Global)
app.use(globalLimiter);

// CORS - No restrictions
app.use(cors());

// Request Logging
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl} - IP: ${req.ip}`);
  next();
});


app.use(express.json({ limit: '15mb' })); // Increased for base64 files
app.use(express.urlencoded({ extended: true, limit: '15mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// API Routes
app.use('/api/auth', authRoutes);
app.use('/api', appRoutes);
app.use('/api/appointments', appointmentRoutes);
app.use('/api/user', profileRoutes); 
app.use('/api', recordRoutes);
// Health Check Route
app.get('/api/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState;
  const dbStatusMap = {
    0: 'disconnected',
    1: 'connected', 
    2: 'connecting',
    3: 'disconnecting'
  };

  res.status(200).json({
    success: true,
    message: 'Server is running optimally',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    database: {
      status: dbStatusMap[dbStatus] || 'unknown',
      connected: dbStatus === 1
    },
    uptime: process.uptime(),
    memory: {
      used: process.memoryUsage().rss,
      heapUsed: process.memoryUsage().heapUsed,
      heapTotal: process.memoryUsage().heapTotal
    }
  });
});

// Root Route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to ExamVerified API',
    version: '1.0.0',
    status: 'Active 🚀',
    timestamp: new Date().toISOString(),
    documentation: 'Check /api/health for system status',
    endpoints: {
      auth: {
        signup: 'POST /api/auth/signup',
        verifyOtp: 'POST /api/auth/verify-otp',
        resendOtp: 'POST /api/auth/resend-otp',
        signin: 'POST /api/auth/signin',
        profile: 'GET /api/auth/profile',
        forgotPassword: 'POST /api/auth/forgot-password',
        resetPassword: 'POST /api/auth/reset-password'
      },
      app: {
        status: 'GET /api/status',
        users: 'GET /api/users',
        createUser: 'POST /api/users'
      },
      system: {
        health: 'GET /api/health'
      }
    }
  });
});

// Status route
app.get('/api/status', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1;
  
  res.status(200).json({
    success: true,
    message: 'API is running successfully',
    database: {
      status: dbStatus ? 'connected' : 'disconnected',
      connected: dbStatus
    },
    server: {
      port: process.env.PORT,
      environment: process.env.NODE_ENV || 'development',
    },
    timestamp: new Date().toISOString(),
  });
});

// 404 Handler - FIXED: Use proper express 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    requestedUrl: req.originalUrl,
    availableEndpoints: [
      '/',
      '/api/health',
      '/api/status',
      '/api/auth/signup',
      '/api/auth/signin',
      '/api/auth/verify-otp',
      '/api/auth/forgot-password',
      '/api/auth/reset-password',
      '/api/auth/profile',
      '/api/users'
    ]
  });
});

// Global Error Handling Middleware
app.use((error, req, res, next) => {
  console.error('Error:', error.message);

  // Mongoose Validation Error
  if (error.name === 'ValidationError') {
    const errors = Object.values(error.errors).map(err => err.message);
    return res.status(400).json({
      success: false,
      message: 'Validation Error',
      errors
    });
  }

  // Mongoose Duplicate Key Error
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return res.status(409).json({
      success: false,
      message: `${field} already exists`
    });
  }

  // JWT Errors
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }

  if (error.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Token expired'
    });
  }

  // Default Error
  res.status(500).json({
    success: false,
    message: 'Internal Server Error'
  });
});

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log(`
🚀 Server running on port ${PORT}
📧 Email verification system ready
🏠 Home: http://localhost:${PORT}/
🔗 Status: http://localhost:${PORT}/api/status
  `);
});

export default app;