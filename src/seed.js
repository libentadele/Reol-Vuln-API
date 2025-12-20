const { User, MedicalRecord } = require('./models');

async function seedDatabase() {
  try {
    // clear old data
    await User.deleteMany({});
    await MedicalRecord.deleteMany({});
    console.log('Cleared existing data');
  } catch (e) {
    console.log('No existing data to clear');
  }

  console.log('Seeding vulnerable server...');

  // create admin users
  const admin = await User.create({
    username: 'admin',
    password: 'secret123',
    role: 'admin',
    fullName: 'System Administrator',
    ssn: '999-00-9999'
  });

  const admin2 = await User.create({
    username: 'superadmin',
    password: 'admin456',
    role: 'admin',
    fullName: 'Super Administrator',
    ssn: '888-77-8888'
  });

  // create doctor users
  const doctor = await User.create({
    username: 'doctor1',
    password: 'doctor123',
    role: 'doctor',
    fullName: 'Dr. House',
    ssn: '123-45-6789'
  });

  const doctor2 = await User.create({
    username: 'doctor2',
    password: 'doctor456',
    role: 'doctor',
    fullName: 'Dr. Watson',
    ssn: '234-56-7890'
  });

  // create patient users
  const patient1 = await User.create({
    username: 'patient1',
    password: 'patient123',
    role: 'patient',
    fullName: 'John Doe',
    ssn: '000-11-2222'
  });

  const patient2 = await User.create({
    username: 'patient2',
    password: 'patient123',
    role: 'patient',
    fullName: 'Jane Smith',
    ssn: '000-33-4444'
  });

  const patient3 = await User.create({
    username: 'patient3',
    password: 'patient789',
    role: 'patient',
    fullName: 'Bob Johnson',
    ssn: '111-22-3333'
  });

  const patient4 = await User.create({
    username: 'patient4',
    password: 'patient999',
    role: 'patient',
    fullName: 'Alice Williams',
    ssn: '222-33-4444'
  });

  // create medical records
  await MedicalRecord.create({
    patientId: patient1._id.toString(),
    diagnosis: 'Allergies',
    medications: ['Loratadine'],
    notes: 'Sensitive PII - Patient has severe allergic reactions to pollen',
    date: '2023-10-01'
  });

  await MedicalRecord.create({
    patientId: patient2._id.toString(),
    diagnosis: 'Hypertension',
    medications: ['Lisinopril'],
    notes: 'Sensitive PII - Patient requires regular blood pressure monitoring',
    date: '2023-10-05'
  });

  await MedicalRecord.create({
    patientId: patient3._id.toString(),
    diagnosis: 'Diabetes Type 2',
    medications: ['Metformin', 'Insulin'],
    notes: 'Sensitive PII - Patient needs regular glucose monitoring',
    date: '2023-10-10'
  });

  await MedicalRecord.create({
    patientId: patient4._id.toString(),
    diagnosis: 'Asthma',
    medications: ['Albuterol', 'Prednisone'],
    notes: 'Sensitive PII - Patient has exercise-induced asthma',
    date: '2023-10-15'
  });

  console.log('Seed complete');
  console.log(`Created ${await User.countDocuments()} users and ${await MedicalRecord.countDocuments()} medical records`);
}

module.exports = { seedDatabase };
