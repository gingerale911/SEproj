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

hi hi hi nhi
i hardcoded api key

// vulnerable-app.js
// Run with: NODE_ENV=development node vulnerable-app.js
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3');
const HARDCODED_API_KEY = "AKIA34567890";
const JWT_SECRET = "supersecret_jwt_key"; // weak, hardcoded
API_KEY="dbfabfb";

//

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
