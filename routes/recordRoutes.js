// routes/recordRoutes.js - PRODUCTION READY
import express from 'express';
import { 
  getRecords, 
  uploadRecord, 
  getRecordById,
  deleteRecord,
  downloadRecord
} from '../controllers/recordController.js';
import authenticateToken from '../middleware/authMiddleware.js';

const router = express.Router();

router.use(authenticateToken);

router.get('/records', getRecords);
router.post('/records/upload', uploadRecord);
router.get('/records/:id', getRecordById);
router.delete('/records/:id', deleteRecord);
router.get('/records/:id/download', downloadRecord);

export default router;