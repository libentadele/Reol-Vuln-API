const bcrypt = require('bcryptjs');
const { User, MedicalRecord } = require('../src/models');

async function seedPatched() {
  try {
    await User.deleteMany({});
    await MedicalRecord.deleteMany({});
  } catch (e) {}

  const makeHash = (p) => bcrypt.hashSync(p, 10);

  const admin = await User.create({ username: 'admin', password: makeHash('secret123'), role: 'admin', fullName: 'System Administrator', ssn: '999-00-9999' });
  const admin2 = await User.create({ username: 'superadmin', password: makeHash('admin456'), role: 'admin', fullName: 'Super Administrator', ssn: '888-77-8888' });

  const doctor = await User.create({ username: 'doctor1', password: makeHash('doctor123'), role: 'doctor', fullName: 'Dr. House', ssn: '123-45-6789' });
  const doctor2 = await User.create({ username: 'doctor2', password: makeHash('doctor456'), role: 'doctor', fullName: 'Dr. Watson', ssn: '234-56-7890' });

  const patient1 = await User.create({ username: 'patient1', password: makeHash('patient123'), role: 'patient', fullName: 'John Doe', ssn: '000-11-2222' });
  const patient2 = await User.create({ username: 'patient2', password: makeHash('patient123'), role: 'patient', fullName: 'Jane Smith', ssn: '000-33-4444' });
  const patient3 = await User.create({ username: 'patient3', password: makeHash('patient789'), role: 'patient', fullName: 'Bob Johnson', ssn: '111-22-3333' });
  const patient4 = await User.create({ username: 'patient4', password: makeHash('patient999'), role: 'patient', fullName: 'Alice Williams', ssn: '222-33-4444' });

  await MedicalRecord.create({ patientId: patient1._id.toString(), diagnosis: 'Allergies', medications: ['Loratadine'], notes: 'Sensitive PII', date: '2023-10-01' });
  await MedicalRecord.create({ patientId: patient2._id.toString(), diagnosis: 'Hypertension', medications: ['Lisinopril'], notes: 'Sensitive PII', date: '2023-10-05' });
  await MedicalRecord.create({ patientId: patient3._id.toString(), diagnosis: 'Diabetes Type 2', medications: ['Metformin'], notes: 'Sensitive PII', date: '2023-10-10' });
  await MedicalRecord.create({ patientId: patient4._id.toString(), diagnosis: 'Asthma', medications: ['Albuterol'], notes: 'Sensitive PII', date: '2023-10-15' });

  console.log('Patched seed complete');
}

module.exports = { seedPatched };
