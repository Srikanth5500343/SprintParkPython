from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
import mysql.connector
import re
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

app = Flask(__name__)

# Secret key for JWT
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.secret_key = 'your_flask_secret_key'

# MySQL connection details
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '5500',
    'database': 'sprintparkwebsite'
}

def get_db_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

# Password Validation Function
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
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    created_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed."}), 500

    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, full_name, designation, reporting_manager, employee_id, mobile_number, location, date_of_birth, blood_group, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (username, email, password_hash, full_name, designation, reporting_manager, employee_id, mobile_number, location, date_of_birth, blood_group, 'active', created_at))
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
    try:
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
            cursor.execute('SELECT email, password_hash, status, full_name, designation, reporting_manager, employee_id FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()

            if not user:
                return jsonify({"error": "User does not exist."}), 404

            if user['status'] != 'active':
                return jsonify({"error": "Account is not active."}), 403

            # Check if the stored hash matches the provided password
            if check_password_hash(user['password_hash'], password):
                # Generate JWT token
                payload = {
                    'username': username,
                    'full_name': user['full_name'],
                    'employee_id': user['employee_id'],
                    'iat': datetime.utcnow(),  # Issued at (start time)
                   
                    'exp': datetime.utcnow() + timedelta(hours=1)
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

    except Exception as e:
        print(f"Error during signin: {str(e)}")
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

# Forgot Password Endpoint
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
        password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        cursor.execute('UPDATE users SET password_hash = %s WHERE username = %s', (password_hash, username))
        conn.commit()

        return jsonify({"status": "success", "message": f"Password successfully updated for {username}."}), 200

    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
