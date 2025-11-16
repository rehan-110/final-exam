// controllers/recordController.js - PRODUCTION READY
import Record from '../models/Record.js';
import mongoose from 'mongoose';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { promisify } from 'util';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const writeFile = promisify(fs.writeFile);
const mkdir = promisify(fs.mkdir);
const access = promisify(fs.access);

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

// Helper function to validate file from base64
const validateFileFromBase64 = (base64String, originalName) => {
  if (!base64String) {
    return 'No file data provided';
  }

  if (!base64String.includes('base64,')) {
    return 'Invalid file format. Please use base64 encoding.';
  }

  const matches = base64String.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
  if (!matches || matches.length !== 3) {
    return 'Invalid base64 file data';
  }

  const mimeType = matches[1];
  const base64Data = matches[2];
  
  try {
    const buffer = Buffer.from(base64Data, 'base64');
    
    const maxSize = 10 * 1024 * 1024;
    if (buffer.length > maxSize) {
      return 'File size must be less than 10MB';
    }

    const allowedMimeTypes = [
      'application/pdf',
      'image/jpeg',
      'image/jpg',
      'image/png',
      'image/gif',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'text/plain'
    ];

    if (!allowedMimeTypes.includes(mimeType)) {
      return 'Invalid file type. Allowed types: PDF, JPEG, PNG, GIF, DOC, DOCX, TXT';
    }

    return {
      isValid: true,
      mimeType,
      buffer,
      size: buffer.length
    };
  } catch (error) {
    return 'Failed to process file data';
  }
};

// Helper function to get file type category
const getFileType = (mimeType) => {
  if (!mimeType) return 'other';
  if (mimeType.startsWith('image/')) return 'image';
  if (mimeType === 'application/pdf') return 'pdf';
  if (mimeType.includes('word') || mimeType.includes('document')) return 'document';
  if (mimeType === 'text/plain') return 'document';
  return 'other';
};

// Helper function to get file extension from mime type
const getFileExtension = (mimeType) => {
  const extensions = {
    'application/pdf': '.pdf',
    'image/jpeg': '.jpg',
    'image/jpg': '.jpg',
    'image/png': '.png',
    'image/gif': '.gif',
    'application/msword': '.doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
    'text/plain': '.txt'
  };
  return extensions[mimeType] || '.bin';
};

// Helper function to get file category
const getFileCategory = (originalName, mimeType) => {
  if (!originalName) return 'other';
  const name = originalName.toLowerCase();
  
  if (name.includes('lab') || name.includes('test') || name.includes('report')) return 'lab_report';
  if (name.includes('prescription') || name.includes('medication')) return 'prescription';
  if (name.includes('scan') || name.includes('mri') || name.includes('ct')) return 'scan';
  if (name.includes('xray') || name.includes('x-ray') || name.includes('radiograph')) return 'xray';
  if (name.includes('history') || name.includes('medical')) return 'medical_history';
  
  return 'other';
};

// 6.4.1 Get Records API
export const getRecords = async (req, res) => {
  try {
    const patientId = req.userId;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const category = req.query.category;
    const sortBy = req.query.sortBy || 'uploadDate';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;

    const query = { 
      patient: patientId, 
      isDeleted: false 
    };

    if (category && category !== 'all') {
      query.category = category;
    }

    const records = await Record.find(query)
      .select('-__v')
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(limit)
      .lean();

    const totalRecords = await Record.countDocuments(query);

    const formattedRecords = records.map(record => ({
      id: record._id,
      title: record.title,
      description: record.description,
      fileType: record.fileType,
      fileName: record.fileName,
      fileSize: record.fileSize,
      formattedFileSize: record.formattedFileSize,
      fileUrl: record.fileUrl,
      category: record.category,
      uploadDate: record.uploadDate,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt
    }));

    const categoryStats = await Record.aggregate([
      { $match: { patient: new mongoose.Types.ObjectId(patientId), isDeleted: false } },
      { $group: { _id: '$category', count: { $sum: 1 } } }
    ]);

    const { statusCode, response } = formatResponse(
      true,
      'Records retrieved successfully',
      {
        records: formattedRecords,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalRecords / limit),
          totalRecords,
          hasNext: page < Math.ceil(totalRecords / limit),
          hasPrev: page > 1
        },
        statistics: {
          totalRecords,
          byCategory: categoryStats.reduce((acc, stat) => {
            acc[stat._id] = stat.count;
            return acc;
          }, {})
        }
      }
    );

    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Get records error:', error.message);
    const { statusCode, response } = formatResponse(false, 'Failed to retrieve records', null, 500);
    res.status(statusCode).json(response);
  }
};

// 6.4.2 Upload Record API
export const uploadRecord = async (req, res) => {
  try {
    const patientId = req.userId;
    const { title, description, category, fileName, fileData } = req.body;

    if (!title || !title.trim()) {
      const { statusCode, response } = formatResponse(false, 'Record title is required', null, 400);
      return res.status(statusCode).json(response);
    }

    if (!fileName) {
      const { statusCode, response } = formatResponse(false, 'File name is required', null, 400);
      return res.status(statusCode).json(response);
    }

    if (!fileData) {
      const { statusCode, response } = formatResponse(false, 'File data is required', null, 400);
      return res.status(statusCode).json(response);
    }

    const fileValidation = validateFileFromBase64(fileData, fileName);
    if (typeof fileValidation === 'string') {
      const { statusCode, response } = formatResponse(false, fileValidation, null, 400);
      return res.status(statusCode).json(response);
    }

    const { mimeType, buffer, size } = fileValidation;

    const uploadsDir = path.join(__dirname, '../uploads/records');
    try {
      await access(uploadsDir);
    } catch (error) {
      await mkdir(uploadsDir, { recursive: true });
    }

    const fileExtension = getFileExtension(mimeType);
    const uniqueFileName = `record_${patientId}_${Date.now()}${fileExtension}`;
    const filePath = path.join(uploadsDir, uniqueFileName);
    await writeFile(filePath, buffer);

    const record = new Record({
      patient: patientId,
      title: title.trim(),
      description: description ? description.trim() : '',
      fileType: getFileType(mimeType),
      fileName: fileName,
      fileSize: size,
      fileUrl: `/uploads/records/${uniqueFileName}`,
      category: category || getFileCategory(fileName, mimeType)
    });

    const savedRecord = await record.save();

    const recordData = {
      id: savedRecord._id,
      title: savedRecord.title,
      description: savedRecord.description,
      fileType: savedRecord.fileType,
      fileName: savedRecord.fileName,
      fileSize: savedRecord.fileSize,
      formattedFileSize: savedRecord.formattedFileSize,
      fileUrl: savedRecord.fileUrl,
      category: savedRecord.category,
      uploadDate: savedRecord.uploadDate
    };

    const { statusCode, response } = formatResponse(
      true,
      'Record uploaded successfully',
      recordData,
      201
    );

    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Upload record error:', error.message);
    
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      const { statusCode, response } = formatResponse(false, 'Validation error: ' + errors.join(', '), null, 400);
      return res.status(statusCode).json(response);
    }

    const { statusCode, response } = formatResponse(false, 'Failed to upload record', null, 500);
    res.status(statusCode).json(response);
  }
};

// Get record by ID
export const getRecordById = async (req, res) => {
  try {
    const { id } = req.params;
    const patientId = req.userId;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      const { statusCode, response } = formatResponse(false, 'Invalid record ID', null, 400);
      return res.status(statusCode).json(response);
    }

    const record = await Record.findOne({
      _id: id,
      patient: patientId,
      isDeleted: false
    }).select('-__v').lean();

    if (!record) {
      const { statusCode, response } = formatResponse(false, 'Record not found', null, 404);
      return res.status(statusCode).json(response);
    }

    const recordData = {
      id: record._id,
      title: record.title,
      description: record.description,
      fileType: record.fileType,
      fileName: record.fileName,
      fileSize: record.fileSize,
      formattedFileSize: record.formattedFileSize,
      fileUrl: record.fileUrl,
      category: record.category,
      uploadDate: record.uploadDate,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt
    };

    const { statusCode, response } = formatResponse(
      true,
      'Record retrieved successfully',
      recordData
    );

    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Get record by ID error:', error.message);
    const { statusCode, response } = formatResponse(false, 'Failed to retrieve record', null, 500);
    res.status(statusCode).json(response);
  }
};

// Delete record
export const deleteRecord = async (req, res) => {
  try {
    const { id } = req.params;
    const patientId = req.userId;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      const { statusCode, response } = formatResponse(false, 'Invalid record ID', null, 400);
      return res.status(statusCode).json(response);
    }

    const record = await Record.findOneAndUpdate(
      {
        _id: id,
        patient: patientId,
        isDeleted: false
      },
      {
        isDeleted: true,
        updatedAt: new Date()
      },
      { new: true }
    );

    if (!record) {
      const { statusCode, response } = formatResponse(false, 'Record not found', null, 404);
      return res.status(statusCode).json(response);
    }

    const { statusCode, response } = formatResponse(true, 'Record deleted successfully');
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Delete record error:', error.message);
    const { statusCode, response } = formatResponse(false, 'Failed to delete record', null, 500);
    res.status(statusCode).json(response);
  }
};

// Download record file
export const downloadRecord = async (req, res) => {
  try {
    const { id } = req.params;
    const patientId = req.userId;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid record ID' });
    }

    const record = await Record.findOne({
      _id: id,
      patient: patientId,
      isDeleted: false
    });

    if (!record) {
      return res.status(404).json({ error: 'Record not found' });
    }

    const filePath = path.join(__dirname, '..', record.fileUrl);
    
    try {
      await access(filePath);
    } catch (error) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${record.fileName}"`);
    
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);

  } catch (error) {
    console.error('Download record error:', error.message);
    res.status(500).json({ error: 'Failed to download record' });
  }
};