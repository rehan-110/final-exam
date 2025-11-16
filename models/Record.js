// models/Record.js
import mongoose from 'mongoose';

const recordSchema = new mongoose.Schema({
  patient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Patient is required']
  },
  title: {
    type: String,
    required: [true, 'Record title is required'],
    trim: true,
    maxlength: [100, 'Title cannot exceed 100 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  fileType: {
    type: String,
    required: [true, 'File type is required'],
    enum: ['pdf', 'image', 'document', 'lab_report', 'prescription', 'other']
  },
  fileName: {
    type: String,
    required: [true, 'File name is required']
  },
  fileSize: {
    type: Number,
    required: [true, 'File size is required']
  },
  fileUrl: {
    type: String,
    required: [true, 'File URL is required']
  },
  uploadDate: {
    type: Date,
    default: Date.now
  },
  category: {
    type: String,
    enum: ['lab_report', 'prescription', 'scan', 'xray', 'medical_history', 'other'],
    default: 'other'
  },
  isDeleted: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

// Indexes for better performance
recordSchema.index({ patient: 1, uploadDate: -1 });
recordSchema.index({ category: 1 });
recordSchema.index({ isDeleted: 1 });

// Virtual for formatted file size
recordSchema.virtual('formattedFileSize').get(function() {
  if (this.fileSize < 1024) {
    return this.fileSize + ' B';
  } else if (this.fileSize < 1048576) {
    return (this.fileSize / 1024).toFixed(2) + ' KB';
  } else {
    return (this.fileSize / 1048576).toFixed(2) + ' MB';
  }
});

export default mongoose.model('Record', recordSchema);