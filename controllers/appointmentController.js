import Appointment from '../models/appointment.js';
import mongoose from 'mongoose';

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

// Helper function to validate appointment time
const validateAppointmentTime = (appointmentDate, appointmentTime) => {
  const now = new Date();
  const appointmentDateTime = new Date(`${appointmentDate}T${appointmentTime}`);
  
  // Check if appointment is in the past
  if (appointmentDateTime < now) {
    return 'Appointment time cannot be in the past';
  }
  
  // Check if appointment is too far in the future (max 6 months)
  const maxDate = new Date();
  maxDate.setMonth(maxDate.getMonth() + 6);
  if (appointmentDateTime > maxDate) {
    return 'Appointments can only be booked up to 6 months in advance';
  }
  
  // Check if it's within business hours (9 AM - 6 PM)
  const hour = appointmentDateTime.getHours();
  if (hour < 9 || hour >= 18) {
    return 'Appointments can only be booked between 9 AM and 6 PM';
  }
  
  // Check if it's a valid time slot (30-minute intervals)
  const minutes = appointmentDateTime.getMinutes();
  if (minutes % 30 !== 0) {
    return 'Appointments must be scheduled in 30-minute intervals';
  }
  
  return null;
};

// 6.2.1 Book Appointment API
export const bookAppointment = async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { doctor, department, appointmentDate, appointmentTime, duration = 30, symptoms, notes } = req.body;
    const patientId = req.userId;

    // Validate required fields
    if (!doctor || !department || !appointmentDate || !appointmentTime) {
      const { statusCode, response } = formatResponse(false, 'Doctor, department, date, and time are required', null, 400);
      return res.status(statusCode).json(response);
    }

    // Validate appointment time
    const timeValidationError = validateAppointmentTime(appointmentDate, appointmentTime);
    if (timeValidationError) {
      const { statusCode, response } = formatResponse(false, timeValidationError, null, 400);
      return res.status(statusCode).json(response);
    }

    // Validate duration
    if (duration < 15 || duration > 120) {
      const { statusCode, response } = formatResponse(false, 'Duration must be between 15 and 120 minutes', null, 400);
      return res.status(statusCode).json(response);
    }

    // Check for time clashes
    const hasTimeClash = await Appointment.checkTimeClash(doctor, appointmentDate, appointmentTime, duration);
    
    if (hasTimeClash) {
      const { statusCode, response } = formatResponse(false, 'This time slot is already booked. Please choose another time.', null, 409);
      return res.status(statusCode).json(response);
    }

    // Create new appointment
    const appointment = new Appointment({
      patient: patientId,
      doctor: doctor.trim(),
      department: department.trim(),
      appointmentDate: new Date(appointmentDate),
      appointmentTime,
      duration,
      symptoms: symptoms ? symptoms.trim() : '',
      notes: notes ? notes.trim() : ''
    });

    const savedAppointment = await appointment.save({ session });

    // Generate meeting link
    const meetingLink = `https://meet.examverified.com/appointment-${savedAppointment._id}`;
    savedAppointment.meetingLink = meetingLink;
    await savedAppointment.save({ session });

    await session.commitTransaction();

    // Prepare response data
    const appointmentData = {
      id: savedAppointment._id,
      doctor: savedAppointment.doctor,
      department: savedAppointment.department,
      appointmentDate: savedAppointment.appointmentDate,
      appointmentTime: savedAppointment.appointmentTime,
      duration: savedAppointment.duration,
      status: savedAppointment.status,
      symptoms: savedAppointment.symptoms,
      notes: savedAppointment.notes,
      meetingLink: savedAppointment.meetingLink,
      bookedAt: savedAppointment.bookedAt
    };

    console.log(`Appointment booked successfully - ID: ${savedAppointment._id}, Patient: ${patientId}, Doctor: ${doctor}`);

    const { statusCode, response } = formatResponse(
      true,
      'Appointment booked successfully!',
      appointmentData,
      201
    );
    res.status(statusCode).json(response);

  } catch (error) {
    await session.abortTransaction();
    
    console.error('Book appointment error:', {
      error: error.message,
      stack: error.stack,
      userId: req.userId,
      timestamp: new Date().toISOString()
    });

    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      const { statusCode, response } = formatResponse(false, 'Validation error: ' + errors.join(', '), null, 400);
      return res.status(statusCode).json(response);
    }

    if (error.code === 11000) {
      const { statusCode, response } = formatResponse(false, 'Appointment conflict detected', null, 409);
      return res.status(statusCode).json(response);
    }

    const { statusCode, response } = formatResponse(false, 'Failed to book appointment. Please try again.', null, 500);
    res.status(statusCode).json(response);
  } finally {
    session.endSession();
  }
};

// 6.2.2 Upcoming Appointments API
export const getUpcomingAppointments = async (req, res) => {
  try {
    const patientId = req.userId;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const now = new Date();

    const upcomingAppointments = await Appointment.find({
      patient: patientId,
      appointmentDate: { $gte: now },
      status: 'scheduled'
    })
    .select('-__v')
    .sort({ appointmentDate: 1, appointmentTime: 1 })
    .skip(skip)
    .limit(limit)
    .lean();

    const totalUpcoming = await Appointment.countDocuments({
      patient: patientId,
      appointmentDate: { $gte: now },
      status: 'scheduled'
    });

    const formattedAppointments = upcomingAppointments.map(appointment => ({
      id: appointment._id,
      doctor: appointment.doctor,
      department: appointment.department,
      appointmentDate: appointment.appointmentDate,
      appointmentTime: appointment.appointmentTime,
      duration: appointment.duration,
      status: appointment.status,
      symptoms: appointment.symptoms,
      notes: appointment.notes,
      meetingLink: appointment.meetingLink,
      bookedAt: appointment.bookedAt
    }));

    const { statusCode, response } = formatResponse(
      true,
      'Upcoming appointments retrieved successfully',
      {
        appointments: formattedAppointments,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalUpcoming / limit),
          totalAppointments: totalUpcoming,
          hasNext: page < Math.ceil(totalUpcoming / limit),
          hasPrev: page > 1
        }
      }
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Get upcoming appointments error:', {
      error: error.message,
      stack: error.stack,
      userId: req.userId,
      timestamp: new Date().toISOString()
    });

    const { statusCode, response } = formatResponse(false, 'Failed to retrieve upcoming appointments', null, 500);
    res.status(statusCode).json(response);
  }
};

// 6.2.3 History API
export const getAppointmentHistory = async (req, res) => {
  try {
    const patientId = req.userId;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const now = new Date();

    const historyAppointments = await Appointment.find({
      patient: patientId,
      $or: [
        { appointmentDate: { $lt: now } },
        { status: { $in: ['completed', 'cancelled', 'no-show'] } }
      ]
    })
    .select('-__v')
    .sort({ appointmentDate: -1, appointmentTime: -1 })
    .skip(skip)
    .limit(limit)
    .lean();

    const totalHistory = await Appointment.countDocuments({
      patient: patientId,
      $or: [
        { appointmentDate: { $lt: now } },
        { status: { $in: ['completed', 'cancelled', 'no-show'] } }
      ]
    });

    const formattedAppointments = historyAppointments.map(appointment => ({
      id: appointment._id,
      doctor: appointment.doctor,
      department: appointment.department,
      appointmentDate: appointment.appointmentDate,
      appointmentTime: appointment.appointmentTime,
      duration: appointment.duration,
      status: appointment.status,
      symptoms: appointment.symptoms,
      notes: appointment.notes,
      meetingLink: appointment.meetingLink,
      bookedAt: appointment.bookedAt
    }));

    const { statusCode, response } = formatResponse(
      true,
      'Appointment history retrieved successfully',
      {
        appointments: formattedAppointments,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalHistory / limit),
          totalAppointments: totalHistory,
          hasNext: page < Math.ceil(totalHistory / limit),
          hasPrev: page > 1
        }
      }
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Get appointment history error:', {
      error: error.message,
      stack: error.stack,
      userId: req.userId,
      timestamp: new Date().toISOString()
    });

    const { statusCode, response } = formatResponse(false, 'Failed to retrieve appointment history', null, 500);
    res.status(statusCode).json(response);
  }
};

// Additional helper endpoint: Get available time slots
export const getAvailableSlots = async (req, res) => {
  try {
    const { doctor, date } = req.query;

    if (!doctor || !date) {
      const { statusCode, response } = formatResponse(false, 'Doctor and date are required', null, 400);
      return res.status(statusCode).json(response);
    }

    // Validate date
    const appointmentDate = new Date(date);
    if (isNaN(appointmentDate.getTime())) {
      const { statusCode, response } = formatResponse(false, 'Invalid date format', null, 400);
      return res.status(statusCode).json(response);
    }

    // Get all booked slots for the doctor on this date
    const bookedAppointments = await Appointment.find({
      doctor,
      appointmentDate: {
        $gte: new Date(date + 'T00:00:00'),
        $lt: new Date(date + 'T23:59:59')
      },
      status: 'scheduled'
    }).select('appointmentTime duration');

    // Generate all possible slots (9 AM to 6 PM, 30-minute intervals)
    const allSlots = [];
    for (let hour = 9; hour < 18; hour++) {
      for (let minute = 0; minute < 60; minute += 30) {
        const timeString = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}`;
        allSlots.push(timeString);
      }
    }

    // Filter out booked slots
    const bookedTimes = bookedAppointments.map(apt => apt.appointmentTime);
    const availableSlots = allSlots.filter(slot => !bookedTimes.includes(slot));

    const { statusCode, response } = formatResponse(
      true,
      'Available slots retrieved successfully',
      {
        doctor,
        date,
        availableSlots,
        totalAvailable: availableSlots.length,
        businessHours: '9:00 AM - 6:00 PM'
      }
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Get available slots error:', error);
    const { statusCode, response } = formatResponse(false, 'Failed to retrieve available slots', null, 500);
    res.status(statusCode).json(response);
  }
};

// Additional endpoint: Get appointment by ID
export const getAppointmentById = async (req, res) => {
  try {
    const { id } = req.params;
    const patientId = req.userId;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      const { statusCode, response } = formatResponse(false, 'Invalid appointment ID', null, 400);
      return res.status(statusCode).json(response);
    }

    const appointment = await Appointment.findOne({
      _id: id,
      patient: patientId
    }).select('-__v').lean();

    if (!appointment) {
      const { statusCode, response } = formatResponse(false, 'Appointment not found', null, 404);
      return res.status(statusCode).json(response);
    }

    const { statusCode, response } = formatResponse(
      true,
      'Appointment retrieved successfully',
      appointment
    );
    res.status(statusCode).json(response);

  } catch (error) {
    console.error('Get appointment by ID error:', error);
    const { statusCode, response } = formatResponse(false, 'Failed to retrieve appointment', null, 500);
    res.status(statusCode).json(response);
  }
};