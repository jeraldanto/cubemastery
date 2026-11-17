import os
import sqlite3
import json
import secrets
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'database.db')

app = Flask(__name__, static_folder=BASE_DIR)
CORS(app)  # Allow frontend to communicate with backend

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Create Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            phone TEXT,
            email TEXT UNIQUE,
            password TEXT,
            token TEXT,
            is_paid BOOLEAN DEFAULT 0,
            completed_lessons TEXT DEFAULT '[]',
            personal_best REAL
        )
    ''')
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

def get_user_by_token(token):
    if not token: return None
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE token = ?', (token,))
    user = c.fetchone()
    conn.close()
    return user

# Serve frontend directly from Flask
@app.route('/')
def serve_index():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    file_path = os.path.join(BASE_DIR, path)
    if os.path.isfile(file_path):
        return send_from_directory(BASE_DIR, path)
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json or {}
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    phone = data.get('phone')

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    hashed_pw = generate_password_hash(password)
    token = secrets.token_hex(16)

    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO users (name, phone, email, password, token) VALUES (?, ?, ?, ?, ?)',
                  (name, phone, email, hashed_pw, token))
        conn.commit()
        conn.close()
        return jsonify({"message": "User created", "token": token}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json or {}
    email = data.get('email')
    password = data.get('password')

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    
    if user and check_password_hash(user['password'], password):
        token = secrets.token_hex(16)
        c.execute('UPDATE users SET token = ? WHERE id = ?', (token, user['id']))
        conn.commit()
        conn.close()
        return jsonify({"message": "Login successful", "token": token}), 200
    
    conn.close()
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/me', methods=['GET'])
def me():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Unauthorized"}), 401
    token = auth_header.split(' ')[1]
    
    user = get_user_by_token(token)
    if not user:
        return jsonify({"error": "Invalid token"}), 401

    return jsonify({
        "name": user['name'],
        "email": user['email'],
        "phone": user['phone'],
        "is_paid": bool(user['is_paid']),
        "completed_lessons": json.loads(user['completed_lessons']),
        "personal_best": user['personal_best']
    }), 200

@app.route('/api/unlock', methods=['POST'])
def unlock():
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1] if auth_header else ''
    user = get_user_by_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE users SET is_paid = 1 WHERE id = ?', (user['id'],))
    conn.commit()
    conn.close()
    return jsonify({"message": "Unlocked"}), 200

@app.route('/api/progress', methods=['POST'])
def progress():
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1] if auth_header else ''
    user = get_user_by_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401

    completed_lessons = request.json.get('completed_lessons', [])
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE users SET completed_lessons = ? WHERE id = ?', (json.dumps(completed_lessons), user['id']))
    conn.commit()
    conn.close()
    return jsonify({"message": "Progress saved"}), 200

@app.route('/api/pb', methods=['POST'])
def update_pb():
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1] if auth_header else ''
    user = get_user_by_token(token)
    if not user: return jsonify({"error": "Unauthorized"}), 401

    pb = request.json.get('personal_best')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE users SET personal_best = ? WHERE id = ?', (pb, user['id']))
    conn.commit()
    conn.close()
    return jsonify({"message": "PB saved"}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"SQL Database Server running on http://localhost:{port}")
    app.run(host='0.0.0.0', port=port)
