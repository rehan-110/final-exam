import express from 'express';
import { 
  bookAppointment, 
  getUpcomingAppointments, 
  getAppointmentHistory,
  getAvailableSlots,
  getAppointmentById
} from '../controllers/appointmentController.js';
import authenticateToken from '../middleware/authMiddleware.js';

const router = express.Router();

// All appointment routes require authentication
router.use(authenticateToken);

// 6.2.1 Book Appointment API
router.post('/book', bookAppointment);

// 6.2.2 Upcoming Appointments API
router.get('/upcoming', getUpcomingAppointments);

// 6.2.3 History API
router.get('/history', getAppointmentHistory);

// Additional helper endpoints
router.get('/available-slots', getAvailableSlots);
router.get('/:id', getAppointmentById);

export default router;