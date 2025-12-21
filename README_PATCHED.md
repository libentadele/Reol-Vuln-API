Reol-Vuln-API — patched branch

This file documents the `patched` branch which contains a hardened version of the vulnerable API.

What this branch changes
- Rejects MongoDB operator injection (no `$` keys in user input used as queries).
- Validates types for authentication and query parameters.
- Hashes seeded passwords with bcrypt and verifies passwords securely on login.
- Limits and sanitizes search/filter endpoints (no raw JSON→DB queries).
- Masks sensitive fields (e.g., SSN) for non-admin responses.

Quick run (assumes MongoDB running at mongodb://127.0.0.1:27017/vulndb)

1. Install Node dependencies

```bash
npm install
```

2. Seed the database (optional)

```bash
node src/seed.js
```

3. Start the server

```bash
npm start
```

4. The API listens on port 4000 by default. The exploit script in `exploit_script/` targets this URL.

Notes
- The exploit script `exploit_script/nosql_exploit.py` has been left unchanged for demonstration; it should fail against this patched branch when the server is running.
- This branch is intended to be reviewed and merged via a pull request.

