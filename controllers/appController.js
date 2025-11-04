import mongoose from 'mongoose';
import User from '../models/User.js';

// Health check and status
export const getStatus = async (req, res) => {
  try {
    // Check database connection
    const dbStatus = mongoose.connection.readyState;
    const dbStatusMessage = 
      dbStatus === 1 ? 'connected' : 
      dbStatus === 2 ? 'connecting' : 
      dbStatus === 3 ? 'disconnecting' : 'disconnected';

    res.status(200).json({
      success: true,
      message: 'API is running successfully!',
      database: {
        status: dbStatusMessage,
        connected: dbStatus === 1,
      },
      server: {
        port: process.env.PORT,
        environment: process.env.NODE_ENV || 'development',
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message,
    });
  }
};

// Create a sample user
export const createUser = async (req, res) => {
  try {
    const { name, email } = req.body;

    if (!name || !email) {
      return res.status(400).json({
        success: false,
        message: 'Name and email are required',
      });
    }

    const user = new User({
      name,
      email,
    });

    const savedUser = await user.save();

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: savedUser,
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'Email already exists',
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Error creating user',
      error: error.message,
    });
  }
};

// Get all users
export const getUsers = async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: users.length,
      data: users,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching users',
      error: error.message,
    });
  }
};