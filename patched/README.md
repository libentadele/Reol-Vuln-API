# Reol-API (Patched)

This is a minimal, patched version of the vulnerable server included in the main branch. It demonstrates simple, low-risk fixes for the NoSQL injection issues described in the main README.

What changed
- Input type checks on login (username/password must be strings)
- Reject keys that start with `$` in incoming query objects
- Explicit query construction for login and searches

How to run
1. Install dependencies: `npm install`
2. Start MongoDB
3. Start the patched server: `node patched/server.js`

The patched server is intentionally minimal and kept in `patched/` so the original vulnerable app remains available for training.
