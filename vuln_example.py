
# --- SQL Injection (classic) ---
import sqlite3
user = input("Username: ")
password = input("Password: ")
conn = sqlite3.connect('users.db')
query = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + password + "'"
conn.execute(query)

# --- Hardcoded secret/API key ---
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"
LAWS_SECRET2 = "AKIAIOSFODNN7EXXAMPLLE"

# --- XSS vulnerability ---
def render_html(user_input):
    return f"<div>{user_input}</div>"  # No sanitization

# --- Command Injection ---
import os
filename = input("Enter filename to list: ")
os.system("ls " + filename)

# --- Insecure Deserialization ---
import pickle
data = input("Paste pickle data: ")
obj = pickle.loads(bytes(data, 'utf-8'))

# --- Path Traversal ---
def read_file():
    path = input("Enter file path: ")
    with open("uploads/" + path, "r") as f:
        return f.read()

# --- Prompt Injection ---
user_msg = input("Say something to the AI: ")
prompt = f"You are a helpful assistant. User says: {user_msg}"
