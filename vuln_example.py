# Example file with intentional vulnerabilities for RepoGuard-AI testing

import sqlite3
import os

# SQL Injection vulnerability
user_id = input("Enter user id: ")
conn = sqlite3.connect('users.db')
query = f"SELECT * FROM users WHERE id = {user_id}"
conn.execute(query)

# Hardcoded secret/API key
API_KEY = "sk_test_1234567890abcdef"

# XSS vulnerability (for web context)
def render_comment(user_comment):
    return f"<div>{user_comment}</div>"  # No sanitization

# Prompt injection vulnerability
prompt = f"You are a helpful assistant. User says: {input('Say something: ')}"
