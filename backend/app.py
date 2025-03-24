from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from auth import auth_bp
import os

load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES'))

# Q. wtf are these `dev only` and `prod only`?
# A. dev only: local dev works on a policy called HTTP, which is terrible in terms of security
#              so we HAVE to configure the cookies and connections to have terrible security
#
#   prod only: when deployed, we can communicate on HTTPS, and it is secure enough
#              so the cookies shouldn't be insecure purposely

app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token_cookie'
app.config['JWT_COOKIE_SECURE'] = False           # dev only      
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'         # dev only      
# app.config['JWT_COOKIE_SECURE'] = True          # prod only
# app.config['JWT_COOKIE_SAMESITE'] = "None"      # prod only
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_CSRF_PROTECT'] = True

# TODO: Change origin according to React Native stuff
CORS(app, origins=["http://localhost:3000"], supports_credentials=True)

# Register 'blueprints', which are modularised code
# Check auth.py for an example
app.register_blueprint(auth_bp)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))
