import mongoose from 'mongoose';

const appointmentSchema = new mongoose.Schema({
  patient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Patient is required']
  },
  doctor: {
    type: String,
    required: [true, 'Doctor name is required'],
    trim: true
  },
  department: {
    type: String,
    required: [true, 'Department is required'],
    trim: true
  },
  appointmentDate: {
    type: Date,
    required: [true, 'Appointment date is required']
  },
  appointmentTime: {
    type: String,
    required: [true, 'Appointment time is required']
  },
  duration: {
    type: Number,
    default: 30,
    min: 15,
    max: 120
  },
  status: {
    type: String,
    enum: ['scheduled', 'completed', 'cancelled', 'no-show'],
    default: 'scheduled'
  },
  symptoms: {
    type: String,
    trim: true,
    maxlength: 500
  },
  notes: {
    type: String,
    trim: true,
    maxlength: 1000
  },
  meetingLink: {
    type: String,
    trim: true
  },
  bookedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Indexes for better performance
appointmentSchema.index({ patient: 1, appointmentDate: 1 });
appointmentSchema.index({ doctor: 1, appointmentDate: 1 });
appointmentSchema.index({ status: 1 });
appointmentSchema.index({ appointmentDate: 1 });

// Static method to check for time clashes
appointmentSchema.statics.checkTimeClash = async function(doctor, appointmentDate, appointmentTime, duration, excludeAppointmentId = null) {
  const appointmentDateTime = new Date(`${appointmentDate}T${appointmentTime}`);
  const endDateTime = new Date(appointmentDateTime.getTime() + duration * 60000);

  const query = {
    doctor: doctor,
    status: 'scheduled',
    appointmentDate: new Date(appointmentDate),
    $or: [
      {
        // Case 1: New appointment starts during existing appointment
        appointmentTime: appointmentTime
      },
      {
        // Case 2: Time ranges overlap
        $expr: {
          $and: [
            { 
              $lt: [
                { $dateFromString: { dateString: { $concat: [{ $dateToString: { format: "%Y-%m-%d", date: "$appointmentDate" } }, "T", "$appointmentTime"] } } },
                endDateTime
              ]
            },
            {
              $gt: [
                { 
                  $dateAdd: {
                    startDate: { $dateFromString: { dateString: { $concat: [{ $dateToString: { format: "%Y-%m-%d", date: "$appointmentDate" } }, "T", "$appointmentTime"] } } },
                    unit: 'minute',
                    amount: '$duration'
                  }
                },
                appointmentDateTime
              ]
            }
          ]
        }
      }
    ]
  };

  if (excludeAppointmentId) {
    query._id = { $ne: excludeAppointmentId };
  }

  const clashes = await this.find(query);
  return clashes.length > 0;
};

export default mongoose.model('Appointment', appointmentSchema);