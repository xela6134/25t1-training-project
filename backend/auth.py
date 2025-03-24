from flask import Blueprint, jsonify, request
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token, 
    jwt_required, 
    get_jwt_identity, 
    set_access_cookies,
    unset_jwt_cookies, 
    unset_access_cookies
)
import mysql.connector
from dotenv import load_dotenv
import os

load_dotenv()

CONFIG = {
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'host': os.getenv('DB_HOST'),
    'port': int(os.getenv('DB_PORT')),
    'database': os.getenv('DB_NAME')
}

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()

# Black magic which connects to database
def get_db_connection():
    return mysql.connector.connect(**CONFIG)

"""
    Register a new user
    ---
    Creates a new user account with email, password, name and age
    Request body (JSON):
    -    email (str): user's email address (must be unique)
    - password (str): plain text password (will be hashed)
    -     name (str): user's full name
    -      age (int): user's age

    Returns:
    - 201 Created: User registered successfully
    - 400 Bad Request: Missing required fields, invalid inputs
    - 409 Conflict: Email already registered
    - 500 Internal Server Error: Database error
"""
@auth_bp.route('/auth/register', methods=['POST'])
def register():
    # Since this is a POST request, relevant data are stored in the body of the request.
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    age = data.get('age')

    # Input Validation
    if not email or not password or not name or not age:
        return jsonify({"msg": "All fields are required."}), 400

    if len(password) < 8:
        return jsonify({"msg": "Password must be at least 8 characters long."}), 400
    
    try:
        age = int(age)
        if age <= 0 or age > 120:
            return jsonify({"msg": "Age must be between 1 and 120."}), 400
    except ValueError:
        return jsonify({"msg": "Age must be a valid number."}), 400

    # Hash password (obviously because we don't want to store raw passwords in the database)
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Now attempt to connect to the database, then insert the new user's details.
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if email already exists
        email.strip().lower()
        cursor.execute("select id from Users where email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({"msg": "Email already exists."}), 409

        # Insert the new user
        cursor.execute(
            "insert into users (email, password, name, age) values (%s, %s, %s, %s)",
            (email, hashed_password, name, age)
        )
        conn.commit()

        return jsonify({"msg": "Registration successful."}), 201
    except Exception as e:
        print(f"Exception caught: {e}")
        conn.rollback()
        return jsonify({"msg": "Internal server error."}), 500
    finally:
        cursor.close()
        conn.close()

"""
    Log in a user
    ---
    Verifies a user's email and password, then issues a secure JWT in a cookie.

    Request body (JSON):
    -    email (str): user's email address
    - password (str): user's plain text password

    Response:
    - 200 OK: Login successful, JWT set in HttpOnly cookie
    - 400 Bad Request: Missing email or password
    - 401 Unauthorized: Invalid credentials
    - 404 Not Found: No user found with the given email
    - 500 Internal Server Error: Database or server error

    Authentication Process:
    1. The client sends login credentials to /auth/login.
    2. Validates credentials using the database
    3. Backend generates a JWT access token containing the user's ID.
    4. This token is stored in an HttpOnly cookie (not accessible to frontend JavaScript).
    5. On future requests, the cookie is automatically sent and used to identify the user.
"""
@auth_bp.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()  # Normalise email
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"msg": "Email and password are required."}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("select * from Users where email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"msg": "User not found."}), 404
        
        if not bcrypt.check_password_hash(user['password'], password):
            return jsonify({"msg": "Invalid credentials."}), 401

        # Create JWT token using the user's id as identity.
        access_token = create_access_token(identity=user['id'])
        response = jsonify({"msg": "Login successful."})
        
        # Store the JWT token in a secure HttpOnly cookie.
        set_access_cookies(response, access_token)
        return response, 200
    except Exception as e:
        print(f"Exception during login: {e}")
        return jsonify({"msg": "Internal server error."}), 500
    finally:
        cursor.close()
        conn.close()

"""
    Get logged-in user's status
    ---
    Returns the authenticated user's account details.

    Requirements:
    - Valid JWT access token stored in an HttpOnly cookie.

    Returns:
    - 200 OK: JSON object with user's id, email, name, and age
    - 401 Unauthorized: Missing or invalid authentication
    - 404 Not Found: User ID in token doesn't exist in database
    - 500 Internal Server Error: Database or server error
"""
@auth_bp.route('/auth/status', methods=['GET'])
@jwt_required()  # This decorator ensures that a valid JWT is present in the cookie.
def status():
    # Retrieve user identity from the JWT
    current_user_id = get_jwt_identity()
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("select id, email, name, age from Users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"msg": "User not found."}), 404
        
        return jsonify({"user": user}), 200
    except Exception as e:
        print(f"Exception during status retrieval: {e}")
        return jsonify({"msg": "Internal server error."}), 500
    finally:
        cursor.close()
        conn.close()

"""
    Log out a user
    ---
    Unsets the JWT access token from the HttpOnly cookie, effectively logging out the user.

    Requirements:
    - A valid JWT access token must be present (the user is logged in).

    Returns:
    - 200 OK: Logout successful, JWT cookie cleared.
    - 500 Internal Server Error: Database or server error.
"""
@auth_bp.route('/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        response = jsonify({"msg": "Logout successful."})
        # Remove the JWT cookie from the client.
        unset_jwt_cookies(response)
        return response, 200

    except Exception as e:
        print(f"Exception during logout: {e}")
        return jsonify({"msg": "Internal server error."}), 500
