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
import uuid
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

    # Validation
    if not email or not password or not name or not age:
        return jsonify({"msg": "All fields are required."}), 400

    try:
        age = int(age)
        if age <= 0 or age > 120:
            return jsonify({"msg": "Age must be between 1 and 120."}), 400
    except ValueError:
        return jsonify({"msg": "Age must be a valid number."}), 400

    # Hash password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if email already exists
        cursor.execute("select id from Users where email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({"msg": "User ID already exists."}), 409

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

