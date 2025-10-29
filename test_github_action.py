# Test file for GitHub Actions workflow
# This file is a placeholder to demonstrate adding a test file to the repository.

def test_placeholder():
    print("This is a test change for the workflow.")
    assert True
    blajd. jdbgakj kb
buri buri buri buri buria
 blah blah BlockingIOError


blum blum shub

gheorgpoewrbfisb
wnbgvpiysdbv'


i hardcoded api key

// vulnerable-app.js
// Run with: NODE_ENV=development node vulnerable-app.js
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3'); // using sqlite for demo
const { exec } = require('child_process'); // command injection potential
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// VULN: Open CORS - allows any origin
app.use(cors({ origin: '*' }));

// VULN: Hardcoded credentials / secrets
const HARDCODED_API_KEY = "AKIA_FAKE_KEY_1234567890";
const JWT_SECRET = "supersecret_jwt_key"; // weak, hardcoded

// VULN: Insecure password hashing (MD5, no salt)
function weakHash(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}

// Setup insecure sqlite DB
const dbFile = './vuln.db';
if (!fs.existsSync(dbFile)) {
  const db = new sqlite3.Database(dbFile);
  db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)");
    db.run("INSERT INTO users (username, password, role) VALUES ('admin', '" + weakHash('adminpass') + "', 'admin')");
    db.run("INSERT INTO users (username, password, role) VALUES ('bob', '" + weakHash('bobpass') + "', 'user')");
  });
  db.close();
}

// VULN: Verbose error handler that leaks stack traces
app.use(function (err, req, res, next) {
  console.error("ERROR:", err);
  res.status(500).send({ error: err.message, stack: err.stack });
});

// -------------------- Routes --------------------

// VULN: SQL injection via string concatenation
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const db = new sqlite3.Database(dbFile);
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + weakHash(password) + "'";
  db.get(query, (err, row) => {
    if (err) return res.status(500).send("db error");
    if (!row) return res.status(401).send("invalid");
    // VULN: weak session - storing username in cookie without signing/encryption
    res.cookie('session_user', row.username, { httpOnly: false });
    res.send({ message: "logged in", user: row.username });
  });
});

// VULN: Command injection - user input passed to shell
app.get('/ping', (req, res) => {
  const target = req.query.host || 'localhost';
  // BAD: directly embedding user input into shell command
  exec('ping -c 1 ' + target, (error, stdout, stderr) => {
    if (error) return res.status(500).send("exec error");
    res.send("<pre>" + stdout + "</pre>");
  });
});

//
