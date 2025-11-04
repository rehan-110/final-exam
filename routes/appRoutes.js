import express from 'express';
import { getStatus, createUser, getUsers } from '../controllers/appController.js';

const router = express.Router();

// Health check and status route
router.get('/status', getStatus);

// User routes
router.post('/users', createUser);
router.get('/users', getUsers);

export default router;