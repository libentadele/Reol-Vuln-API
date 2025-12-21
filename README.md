##NoSQL Injection – Vulnerable Server (Educational)

This project is a deliberately vulnerable backend application built to demonstrate real NoSQL injection attacks against MongoDB.

It is designed only for learning and security training.
Do NOT deploy this in production.

What This Project Shows

This server demonstrates how poor input validation can allow attackers to:

Bypass login without knowing a password

Gain admin access

Extract sensitive data (users, SSNs, medical records)

Abuse MongoDB operators like:

$ne

$regex

$exists

$gt

All vulnerabilities are real and executed against a real MongoDB database, not mock data.

Tech Stack

Node.js + Express – Backend API

MongoDB + Mongoose – Database

JWT – Authentication

RBAC – Roles (admin, doctor, patient)

Python – Automated exploit script

Requirements

You only need:

Node.js (v14+)

MongoDB (running locally)

Python 3 (for the exploit script)

Quick Setup (Minimal Steps)
1. Start MongoDB

Make sure MongoDB is running on port 27017.

mongod


If MongoDB is already running, skip this.

2. Install Dependencies
npm install
pip3 install requests

3. Start the Server
npm start


Server runs at:

http://localhost:4000


Verify it works:

curl http://localhost:4000/health


Expected response:

{"status":"ok","message":"Vulnerable server is running"}

Seeded Test Accounts

These users are created automatically:

Admin

admin / secret123

superadmin / admin456

Doctor

doctor1 / doctor123

doctor2 / doctor456

Patient

patient1 / patient123

patient2 / patient123

patient3 / patient789

patient4 / patient999

Medical records exist for all patients.

Vulnerable Endpoints (Summary)
Login (Authentication Bypass)
POST /auth/login


Example attack payload:

{
  "username": "admin",
  "password": { "$ne": null }
}


This logs in without knowing the password.

User Search & Filtering
GET  /search
POST /users/filter
GET  /users/find


Attackers can extract all users, admins, and SSNs.

Medical Records
POST /records/search


Attackers can extract all medical records.

Admin Endpoints
POST /admin/export
POST /admin/query
POST /admin/users


Once an attacker gets an admin token, full database exfiltration is possible.

Testing with Postman (Recommended)

Use Postman to clearly show the attacks and take screenshots for proof.

Authentication Bypass Test

Request

Method: POST

URL: http://localhost:4000/auth/login

Body (JSON):

{
  "username": "admin",
  "password": { "$ne": null }
}


Result

Status 200

JWT token returned

Logged in as admin

📸 Insert Postman screenshot here

Data Extraction Test

Request

GET /search?q={"$regex":".*"}


Result

Returns all users with sensitive data

📸 Insert Postman screenshot here

Automated Exploit Script

You can also run the full attack automatically:

python3 exploit/nosql_exploit.py


The script demonstrates:

Injection discovery

Authentication bypass

Full data extraction

This is useful for live demos, but Postman is better for documentation.

Impact Summary

Because of these vulnerabilities:

Anyone can log in as admin

Sensitive data can be stolen

Medical records are exposed

RBAC protections are bypassed

This represents a critical security failure.

Root Cause

User input is passed directly to MongoDB queries

MongoDB operators are not blocked

No input type validation

No query whitelisting

How This Should Be Fixed (High-Level)

Reject objects in login fields (username/password must be strings)

Block $ operators from user input

Build queries manually (no dynamic filters)

Validate input using schema validation

Never accept raw MongoDB queries from users

Important Warning

⚠️ This project is intentionally insecure

For education only

Do not deploy

Do not expose to the internet

License

Educational use only.
