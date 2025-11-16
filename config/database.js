import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config({ debug: false });

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      dbName: 'Members',
      // Add these connection options
      serverSelectionTimeoutMS: 30000, // 30 seconds
      socketTimeoutMS: 45000, // 45 seconds
      maxPoolSize: 10,
      minPoolSize: 5,
      retryWrites: true,
      retryReads: true
    });

    console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
    console.log(`📁 Database: ${conn.connection.name}`);
    return conn;
  } catch (error) {
    console.error('❌ Database connection error:', error.message);
    
    // More detailed error information
    if (error.name === 'MongooseServerSelectionError') {
      console.error('🔧 Network/DNS issue. Check your internet connection and MongoDB cluster settings.');
    }
    
    process.exit(1);
  }
};

export default connectDB;