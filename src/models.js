const { mongoose } = require('./db');
const { Schema } = require('mongoose');

const UserSchema = new Schema({
  username: { type: String, required: true, index: true },
  password: { type: String, required: true },
  role: { type: String, required: true },
  fullName: String,
  ssn: String
}, { collection: 'users' });

const MedicalRecordSchema = new Schema({
  patientId: { type: String, required: true },
  diagnosis: String,
  medications: [String],
  notes: String,
  date: String
}, { collection: 'medicalrecords' });

const User = mongoose.models.User || mongoose.model('User', UserSchema);
const MedicalRecord = mongoose.models.MedicalRecord || mongoose.model('MedicalRecord', MedicalRecordSchema);

module.exports = { User, MedicalRecord };
