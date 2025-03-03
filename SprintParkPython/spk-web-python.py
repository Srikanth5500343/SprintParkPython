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
import traceback
from functools import wraps
from mysql.connector import Error
from flasgger import Swagger, swag_from
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
import pymysql

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Swagger Setup
app.config['SWAGGER'] = {
    "title": "Sprint Park API",
    "uiversion": 3,
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Enter token as: Bearer {your_token}"
        }
    }
}
Swagger(app)

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
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '')
        
        if not token.startswith("Bearer "):
            return jsonify({"error": "Invalid token format. Use 'Bearer <token>'."}), 401
        
        jwt_token = token.split("Bearer ")[1]  # Extract token after "Bearer "
        
        try:
            decoded_token = jwt.decode(jwt_token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user = decoded_token  # Store user data in request for later use
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired. Please login again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token. Please provide a valid token."}), 401

        return f(*args, **kwargs)
    
    return decorated

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
    emailID = data.get('emailID')
    password = data.get('password')  # User's raw password input
    fullName = data.get('fullName')
    designation = data.get('designation')
    reportingManager = data.get('reportingManager')
    department = data.get('department')
    employeeID = data.get('employeeID')
    mobileNumber = data.get('mobileNumber')
    location = data.get('location')
    dateOfBirth = data.get('dateOfBirth')  # Expected format: YYYY-MM-DD
    bloodGroup = data.get('bloodGroup')
    
    # Validate all required fields
    if not all([username, emailID, password, fullName, designation, reportingManager, department, employeeID, mobileNumber, location, dateOfBirth, bloodGroup]):
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
            INSERT INTO employee_details (username, emailID, password, fullName, designation, reportingManager, department, employeeID, mobileNumber, location, dateOfBirth, bloodGroup, status, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (username, emailID, password_hash, fullName, designation, reportingManager, department, employeeID, mobileNumber, location, dateOfBirth, bloodGroup, 'active', created_at, created_at))

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
        return jsonify({"error": "Invalid JSON format. Please check."}), 400

    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({"error": "All fields are required."}), 400

    conn = get_db_connection()
    if not conn:
        print("Database connection failed.")
        return jsonify({"error": "Database connection failed."}), 500

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT * FROM employee_details WHERE username = %s', (username,))
        user = cursor.fetchone()
        print("User Found:", user)

        if not user:
            return jsonify({"error": "User does not exist."}), 404

        if user['status'] != 'active':
            return jsonify({"error": "Account is not active."}), 403

        print("Stored Password Hash:", user['password'])
        print("Entered Password:", password)
        if not check_password_hash(user['password'], password):
            return jsonify({"error": "Invalid password."}), 401

        # Generate JWT Token
        payload = {
            'username': username,
            'fullName': user['fullName'],
            'employeeID': user['employeeID'],
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

        print("Generated Token:", token)

        return jsonify({
            "message": "Signin successful.",
            "token": token,
            "fullName": user["fullName"],
            "designation": user["designation"],
            "reportingManager": user["reportingManager"],
            "department": user["department"],
            "employeeID": user["employeeID"],
            "emailID": user["emailID"]
        }), 200
    except Exception as e:
        print("Error during signin:", str(e))
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error"}), 500
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
        cursor.execute('SELECT username FROM employee_details WHERE username = %s', (username,))
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
        cursor.execute('SELECT username FROM employee_details WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"status": "error", "message": f"Username {username} not found."}), 404
        # Update the password hash
        password = generate_password_hash(new_password, method='pbkdf2:sha256')
        cursor.execute('UPDATE employee_details SET password = %s WHERE username = %s', (password, username))
        conn.commit()
        return jsonify({"status": "success", "message": f"Password successfully updated for {username}."}), 200
    finally:
        cursor.close()
        conn.close()

# Get All Employees Endpoint
@app.route('/getAllEmployees', methods=['GET'])
def get_all_employees():
    designation = request.args.get('designation')  # Optional filter
    location = request.args.get('location')  # Optional filter
    status = request.args.get('status')  # Optional filter (e.g., active/inactive)
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed."}), 500
    
    cursor = conn.cursor(dictionary=True)

    # Base query
    query = "SELECT user_id, username, emailID, fullName, designation, reportingManager, department, status, created_at, updated_at, employeeID, mobileNumber, location, dateOfBirth, bloodGroup FROM employee_details WHERE 1=1"
    values = []

    # Apply filters if provided
    if designation:
        query += " AND designation = %s"
        values.append(designation)
    if location:
        query += " AND location = %s"
        values.append(location)
    if status:
        query += " AND status = %s"
        values.append(status)

    try:
        cursor.execute(query, tuple(values))
        employees = cursor.fetchall()
        return jsonify({"employees": employees}), 200
    finally:
        cursor.close()
        conn.close()

   
# PDF Upload
@app.route('/pdf/upload', methods=['POST'])
def upload_pdf():
    user_id = request.form.get('user_id')
    file = request.files.get('file')
    
    if not user_id or not file:
        return jsonify({"error": "User ID and file are required."}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed."}), 500
    
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO pdf_files (user_id, file_data) VALUES (%s, %s) ON DUPLICATE KEY UPDATE file_data = VALUES(file_data)', (user_id, file.read()))
        conn.commit()
        return jsonify({"message": "File uploaded successfully."}), 200
    finally:
        cursor.close()
        conn.close()


# PDF Download
@app.route('/pdf/download/<int:user_id>', methods=['GET'])
def download_pdf(user_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed."}), 500
    
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT file_data FROM pdf_files WHERE user_id = %s', (user_id,))
        record = cursor.fetchone()
        
        if not record or not record[0]:
            return jsonify({"error": "No PDF found for this user."}), 404
        
        return send_file(io.BytesIO(record[0]), mimetype="application/pdf", as_attachment=True, download_name=f"user_{user_id}.pdf")
    finally:
        cursor.close()
        conn.close()
# PDF View
@app.route('/pdf/view_all', methods=['GET'])
def view_all_pdfs():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed."}), 500
        
        cursor = conn.cursor()
        
        # Fetch all PDFs
        cursor.execute("SELECT user_id FROM pdf_files")  
        records = cursor.fetchall()  # List of tuples [(user_id,), (user_id,)]
        
        cursor.close()
        conn.close()
        
        if not records:
            return jsonify({"error": "No PDFs found."}), 404
        
        # Create response list with download URLs
        pdf_list = [{"user_id": record[0], "download_url": f"{request.host_url}pdf/view/{record[0]}"} for record in records]
        
        return jsonify(pdf_list), 200
    
    except Exception as e:
        print("Error:", e)  # Logs error in console
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


 #leaves   
@app.route('/leaves', methods=['GET'])
@token_required  # Ensure token authentication
def get_user_leaves():
    try:
        # Extract user details from the token (set in @token_required)
        user_data = request.user
        employee_id = user_data.get('employeeID')  # Extract from JWT payload
        
        if not employee_id:
            return jsonify({"error": "Invalid token. Employee ID missing."}), 401

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed."}), 500

        cursor = conn.cursor(dictionary=True)

        # First, get `user_id` from `employee_details` using `employeeID`
        cursor.execute("SELECT user_id FROM employee_details WHERE employeeID = %s", (employee_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found."}), 404

        user_id = user["user_id"]

        # Fetch leave details using `user_id`
        cursor.execute("SELECT * FROM leaves WHERE user_id = %s", (user_id,))
        leaves = cursor.fetchall()

        if not leaves:
            return jsonify({"message": "No leave records found for this user."}), 404

        return jsonify({
            "user_id": user_id,
            "employeeID": employee_id,
            "leaves": leaves
        }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token."}), 401
    except Exception as e:
        print("Error fetching leave records:", e)
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    finally:
        if conn:
            cursor.close()
            conn.close()

SECRET_KEY = "your_secret_key"

def verify_token():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None, "Missing or invalid token"
    
    token = auth_header.split("Bearer ")[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded, None
    except jwt.ExpiredSignatureError:
        return None, "Token has expired"
    except jwt.InvalidTokenError:
        return None, "Invalid token"


@app.route('/attendance', methods=['GET'])
@token_required  # Ensure token authentication
def get_attendance():
    try:
        # Extract user details from the token
        user_data = request.user
        employee_id = user_data.get('employeeID')  # Extract from JWT payload
        
        if not employee_id:
            return jsonify({"error": "Invalid token. Employee ID missing."}), 401
        
        user_id = request.args.get('user_id')  # Get user_id from request query params
        if not user_id:
            return jsonify({"error": "User ID is required."}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed."}), 500

        cursor = conn.cursor(dictionary=True)

        # Verify that the provided user_id matches the token's employeeID
        cursor.execute("SELECT user_id FROM employee_details WHERE employeeID = %s", (employee_id,))
        user = cursor.fetchone()

        if not user or str(user['user_id']) != user_id:
            return jsonify({"error": "Unauthorized access."}), 403

        # Fetch attendance details
        cursor.execute("SELECT * FROM attendance WHERE user_id = %s", (user_id,))
        attendance_records = cursor.fetchall()

        if not attendance_records:
            return jsonify({"message": "No attendance records found for this user."}), 404

        return jsonify({
            "user_id": user_id,
            "employeeID": employee_id,
            "attendance": attendance_records
        }), 200
    
    except Exception as e:
        print("Error fetching attendance records:", e)
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500
    
    finally:
        if conn:
            cursor.close()
            conn.close()

            
if __name__ == '__main__':
    app.run(debug=True, port=5202)
