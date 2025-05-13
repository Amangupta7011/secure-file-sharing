from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, session, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import uuid
from datetime import datetime, timedelta
import jwt
from functools import wraps
from config import Config
from flask_pymongo import PyMongo


app = Flask(__name__)
app.config.from_object(Config)

# Initialize MongoDB
mongo = PyMongo(app)
app = Flask(__name__)
app.config.from_object(Config)

# Initialize MongoDB connection
mongo = PyMongo(app)


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'client_login'

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(email):
    user_data = mongo.db.users.find_one({'email': email})
    if user_data:
        user = User()
        user.id = email
        user.user_type = user_data['user_type']
        return user
    return None

# JWT token required decorator (for API routes)
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = mongo.db.users.find_one({'email': data['email']})
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/')
def home():
    return render_template('base.html')

# Ops User Login
@app.route('/ops/login', methods=['GET', 'POST'])
def ops_login():
    if request.method == 'POST':
        data = request.form
        user_data = mongo.db.users.find_one({'email': data['email'], 'user_type': 'ops'})
        
        if user_data and check_password_hash(user_data['password'], data['password']):
            user = User()
            user.id = user_data['email']
            login_user(user)
            
            # Generate JWT token for API access
            token = jwt.encode({
                'email': user_data['email'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['SECRET_KEY'])
            
            flash('Login successful', 'success')
            return jsonify({'token': token, 'message': 'Login successful'})
        
        flash('Invalid credentials', 'danger')
        return jsonify({'message': 'Invalid credentials'}), 401
    
    return render_template('login.html', user_type='ops')

# Client User Signup
@app.route('/client/signup', methods=['GET', 'POST'])
def client_signup():
    if request.method == 'POST':
        data = request.form
        if mongo.db.users.find_one({'email': data['email']}):
            flash('User already exists', 'danger')
            return jsonify({'message': 'User already exists'}), 400
        
        hashed_password = generate_password_hash(data['password'])
        verification_token = str(uuid.uuid4())
        
        user = {
            'email': data['email'],
            'password': hashed_password,
            'user_type': 'client',
            'verified': False,
            'verification_token': verification_token,
            'created_at': datetime.utcnow()
        }
        mongo.db.users.insert_one(user)
        
        # In production, send verification email here
        verification_url = url_for('verify_email', token=verification_token, _external=True)
        print(f"Verification URL: {verification_url}")  # For demo purposes
        
        flash('Account created! Please check your email for verification.', 'success')
        return jsonify({
            'message': 'User created. Please check your email for verification.',
            'verification_url': verification_url  # Normally not returned, just for demo
        })
    
    return render_template('signup.html')

# Email Verification
@app.route('/verify/<token>')
def verify_email(token):
    user = mongo.db.users.find_one({'verification_token': token})
    if not user:
        flash('Invalid verification token', 'danger')
        return redirect(url_for('client_login'))
    
    mongo.db.users.update_one(
        {'_id': user['_id']},
        {'$set': {'verified': True, 'verification_token': None}}
    )
    
    flash('Email verified successfully! You can now login.', 'success')
    return redirect(url_for('client_login'))

# Client User Login
@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    if request.method == 'POST':
        data = request.form
        user_data = mongo.db.users.find_one({'email': data['email'], 'user_type': 'client'})
        
        if user_data and check_password_hash(user_data['password'], data['password']):
            if not user_data.get('verified'):
                flash('Please verify your email first', 'warning')
                return jsonify({'message': 'Please verify your email first'}), 401
            
            user = User()
            user.id = user_data['email']
            login_user(user)
            
            # Generate JWT token for API access
            token = jwt.encode({
                'email': user_data['email'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['SECRET_KEY'])
            
            flash('Login successful', 'success')
            return jsonify({'token': token, 'message': 'Login successful'})
        
        flash('Invalid credentials', 'danger')
        return jsonify({'message': 'Invalid credentials'}), 401
    
    return render_template('login.html', user_type='client')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

# File Upload (Ops User only)
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if current_user.user_type != 'ops':
        flash('Unauthorized access', 'danger')
        return jsonify({'message': 'Unauthorized'}), 403
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return jsonify({'message': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return jsonify({'message': 'No selected file'}), 400
        
        allowed_extensions = {'pptx', 'docx', 'xlsx'}
        if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            flash('Invalid file type. Only pptx, docx, xlsx allowed.', 'danger')
            return jsonify({'message': 'Invalid file type. Only pptx, docx, xlsx allowed.'}), 400
        
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
        file.save(file_path)
        
        file_data = {
            'file_id': file_id,
            'original_name': filename,
            'uploaded_by': current_user.id,
            'uploaded_at': datetime.utcnow(),
            'download_tokens': []
        }
        mongo.db.files.insert_one(file_data)
        
        flash('File uploaded successfully', 'success')
        return jsonify({'message': 'File uploaded successfully', 'file_id': file_id})
    
    return render_template('upload.html')

# List Files (Client User)
@app.route('/files')
@login_required
def list_files():
    if current_user.user_type != 'client':
        flash('Unauthorized access', 'danger')
        return jsonify({'message': 'Unauthorized'}), 403
    
    files = list(mongo.db.files.find({}, {'_id': 0, 'file_id': 1, 'original_name': 1, 'uploaded_at': 1}))
    return render_template('files.html', files=files)

# Generate Download Link (Client User)
@app.route('/download/<file_id>', methods=['GET'])
@login_required
def generate_download_link(file_id):
    if current_user.user_type != 'client':
        flash('Unauthorized access', 'danger')
        return jsonify({'message': 'Unauthorized'}), 403
    
    file_data = mongo.db.files.find_one({'file_id': file_id})
    if not file_data:
        flash('File not found', 'danger')
        return jsonify({'message': 'File not found'}), 404
    
    download_token = str(uuid.uuid4())
    mongo.db.files.update_one(
        {'file_id': file_id},
        {'$push': {'download_tokens': download_token}}
    )
    
    download_url = url_for('download_file', file_id=file_id, token=download_token, _external=True)
    flash('Download link generated', 'success')
    return jsonify({
        'download-link': download_url,
        'message': 'success'
    })

# Actual File Download
@app.route('/download/<file_id>/<token>', methods=['GET'])
def download_file(file_id, token):
    file_data = mongo.db.files.find_one({'file_id': file_id})
    if not file_data or token not in file_data.get('download_tokens', []):
        flash('Invalid or expired download link', 'danger')
        return jsonify({'message': 'Invalid or expired download link'}), 403
    
    # Remove the used token
    mongo.db.files.update_one(
        {'file_id': file_id},
        {'$pull': {'download_tokens': token}}
    )
    
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        file_id,
        as_attachment=True,
        download_name=file_data['original_name']
    )

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)