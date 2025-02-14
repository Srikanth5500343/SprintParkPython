from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import mysql.connector
import re
import io
import logging
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_swagger_ui import get_swaggerui_blueprint
import jwt
import secrets
from flask import make_response, send_file


app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Swagger Setup
SWAGGER_URL = "/swagger"
API_URL = "/static/swagger.json"
swagger_ui_blueprint = get_swaggerui_blueprint(SWAGGER_URL, API_URL)
app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)

# Database Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'port': '3306',
    'password': '5500',
    'database': 'sprintparkwebsite'
}

def get_db_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

# Password Validation

def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[@$!%*?&]', password):
        return False, "Password must contain at least one special character (@$!%*?&)."
    return True, None

# Signup Endpoint
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    full_name = data.get('full_name')
    designation = data.get('designation')
    reporting_manager = data.get('reporting_manager')
    employee_id = data.get('employee_id')
    mobile_number = data.get('mobile_number')
    location = data.get('location')
    date_of_birth = data.get('date_of_birth')  # Expected format: YYYY-MM-DD
    blood_group = data.get('blood_group')
    if not all([username, email, password, full_name, designation, reporting_manager, employee_id, mobile_number, location, date_of_birth, blood_group]):
        return jsonify({"error": "All fields are required."}), 400
    # Validate password strength
    is_valid, error_msg = is_strong_password(password)
    if not is_valid:
        return jsonify({"error": error_msg}), 400
    # Hash the password before storing it
    password = generate_password_hash(password, method='pbkdf2:sha256')
    created_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed."}), 500
    cursor = conn.cursor()
    try:
        cursor.execute(''' 
            INSERT INTO users (username, email, password, full_name, designation, reporting_manager, employee_id, mobile_number, location, date_of_birth, blood_group, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (username, email, password, full_name, designation, reporting_manager, employee_id, mobile_number, location, date_of_birth, blood_group, 'active', created_at))
        conn.commit()
        return jsonify({"message": "User signed up successfully."}), 201
    except mysql.connector.IntegrityError:
        return jsonify({"error": "Username, email, or employee ID already exists."}), 409
    finally:
        cursor.close()
        conn.close()

# Signin Endpoint
@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Invalid JSON format. Please Check."}), 400
    username = data.get('username')
    password = data.get('password')
    if not all([username, password]):
        return jsonify({"error": "All fields are required."}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed."}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT email, password, status, full_name, designation, reporting_manager, employee_id FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "User does not exist."}), 404
        if user['status'] != 'active':
            return jsonify({"error": "Account is not active."}), 403
        # Check if the stored hash matches the provided password
        if check_password_hash(user['password'], password):
            # Generate JWT token
            payload = {
                'username': username,
                'full_name': user['full_name'],
                'employee_id': user['employee_id'],
                'iat': datetime.utcnow(),  # Issued at (start time)
                'exp': datetime.utcnow() + timedelta(hours=1)  # Expiration time
            }
            token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({
                "message": "Signin successful.",
                "token": token,
                "full_name": user["full_name"],
                "designation": user["designation"],
                "reporting_manager": user["reporting_manager"],
                "employee_id": user["employee_id"],
                "email": user["email"]
            }), 200
        else:
            return jsonify({"error": "Invalid password."}), 401
    finally:
        cursor.close()
        conn.close()
# Forgot Password
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Invalid request. Please send JSON data."}), 400
    username = data.get('username')
    if not username:
        return jsonify({"status": "error", "message": "Please provide a username."}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Database connection failed."}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT username FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"status": "error", "message": f"Username {username} not found."}), 404
        return jsonify({"status": "success", "message": f"User {username} exists. Proceed to reset password."}), 200
    finally:
        cursor.close()
        conn.close()
# Reset Password Endpoint
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Invalid request. Please send JSON data."}), 400
    username = data.get('username')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    if not username or not new_password or not confirm_password:
        return jsonify({"status": "error", "message": "Please fill in all fields."}), 400
    if new_password != confirm_password:
        return jsonify({"status": "error", "message": "Passwords do not match."}), 400
    is_valid, error_msg = is_strong_password(new_password)
    if not is_valid:
        return jsonify({"status": "error", "message": error_msg}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({"status": "error", "message": "Database connection failed."}), 500
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT username FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"status": "error", "message": f"Username {username} not found."}), 404
        # Update the password hash
        password = generate_password_hash(new_password, method='pbkdf2:sha256')
        cursor.execute('UPDATE users SET password = %s WHERE username = %s', (password, username))
        conn.commit()
        return jsonify({"status": "success", "message": f"Password successfully updated for {username}."}), 200
    finally:
        cursor.close()
        conn.close()
# PDF Upload
@app.route('/pdf/upload', methods=['POST'])
def upload_pdf():
    user_id = request.form.get('user_id')
    file = request.files.get('file')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO pdf_files (user_id, file_data) VALUES (%s, %s) ON DUPLICATE KEY UPDATE file_data = VALUES(file_data)', (user_id, file.read()))
    conn.commit()
    return jsonify({"message": "File uploaded successfully."}), 200

# PDF Download
@app.route('/pdf/download/<int:user_id>', methods=['GET'])
def download_pdf(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT file_data FROM pdf_files WHERE user_id = %s', (user_id,))
    record = cursor.fetchone()
    return send_file(io.BytesIO(record[0]), mimetype="application/pdf", as_attachment=True, download_name=f"user_{user_id}.pdf")

if __name__ == '__main__':
    app.run(debug=True, port=5202)
