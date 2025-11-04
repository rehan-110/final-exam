import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    minlength: [2, 'Name must be at least 2 characters long'],
    maxlength: [50, 'Name must be less than 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true, // This creates an index automatically
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email address']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters long']
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  verificationExpires: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  refreshToken: String,
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  lastLoginAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// Remove this duplicate index - it's already created by 'unique: true' above
// userSchema.index({ email: 1 }); // ❌ DELETE THIS LINE

// Keep only the compound indexes that are actually needed
userSchema.index({ isVerified: 1 });
userSchema.index({ createdAt: 1 });
userSchema.index({ resetPasswordExpires: 1 }, { expireAfterSeconds: 0 });

// Index for unique verified emails (keep this one - it's a compound index)
userSchema.index({ email: 1, isVerified: 1 }, { 
  unique: true, 
  partialFilterExpression: { isVerified: true } 
});

export default mongoose.model('User', userSchema);