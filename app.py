"""
Renaper System - Flask Backend Application
Comprehensive backend for document management with authentication, 
security, audit logging, and PDF generation capabilities.
"""

import os
import json
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO

from flask import (
    Flask, request, jsonify, send_file, session, 
    render_template_string, make_response
)
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, 
    get_jwt_identity, get_jwt
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.pdfgen import canvas
import jwt as pyjwt
from cryptography.fernet import Fernet

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Application configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///renaper.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Security
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_ATTEMPT_WINDOW = 900  # 15 minutes
    PASSWORD_MIN_LENGTH = 12
    REQUIRE_2FA = True
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get(
        'RATELIMIT_STORAGE_URL',
        'memory://'
    )
    
    # File upload
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'docx'}
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')

# ============================================================================
# APPLICATION INITIALIZATION
# ============================================================================

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
cors = CORS(app, resources={r"/api/*": {"origins": ["*"]}})
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=app.config['RATELIMIT_STORAGE_URL']
)

# Encryption cipher
cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

# Create logs directory
os.makedirs('logs', exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.FileHandler('logs/audit.log'),
        logging.StreamHandler()
    ]
)

app_logger = logging.getLogger('renaper_app')
audit_logger = logging.getLogger('renaper_audit')

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(db.Model):
    """User model with enhanced security features"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # admin, user, viewer
    
    # Security
    two_fa_enabled = db.Column(db.Boolean, default=False)
    two_fa_secret = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    is_locked = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    documents = db.relationship('Document', backref='owner', lazy=True, cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True, cascade='all, delete-orphan')
    login_attempts = db.relationship('LoginAttempt', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        if len(password) < app.config['PASSWORD_MIN_LENGTH']:
            raise ValueError(f"Password must be at least {app.config['PASSWORD_MIN_LENGTH']} characters")
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'is_active': self.is_active,
            'two_fa_enabled': self.two_fa_enabled,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat()
        }


class Document(db.Model):
    """Document model"""
    __tablename__ = 'documents'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    document_type = db.Column(db.String(50), nullable=False)  # certificate, visa, etc.
    file_path = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(255), nullable=False)  # SHA-256
    file_size = db.Column(db.Integer, nullable=False)
    
    # Metadata
    subject_id = db.Column(db.String(50), nullable=True, index=True)  # Document subject identifier
    subject_name = db.Column(db.String(255), nullable=True)
    issuing_authority = db.Column(db.String(255), nullable=True)
    issue_date = db.Column(db.DateTime, nullable=True)
    expiry_date = db.Column(db.DateTime, nullable=True)
    
    # Status and access control
    status = db.Column(db.String(20), default='active')  # active, archived, revoked
    access_level = db.Column(db.String(20), default='confidential')  # public, internal, confidential
    is_encrypted = db.Column(db.Boolean, default=True)
    
    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    access_logs = db.relationship('AccessLog', backref='document', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'document_type': self.document_type,
            'file_size': self.file_size,
            'subject_id': self.subject_id,
            'subject_name': self.subject_name,
            'status': self.status,
            'access_level': self.access_level,
            'issue_date': self.issue_date.isoformat() if self.issue_date else None,
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None,
            'created_at': self.created_at.isoformat(),
            'owner_id': self.user_id
        }


class AuditLog(db.Model):
    """Audit logging model"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.Integer, nullable=True)
    
    # Details
    details = db.Column(db.JSON, nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(500), nullable=True)
    status = db.Column(db.String(20), default='success')  # success, failure, warning
    
    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'status': self.status,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat(),
            'details': self.details
        }


class AccessLog(db.Model):
    """Document access logging"""
    __tablename__ = 'access_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    access_type = db.Column(db.String(20), nullable=False)  # view, download, print
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    accessing_user = db.relationship('User', foreign_keys=[user_id])


class LoginAttempt(db.Model):
    """Track login attempts for security"""
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    success = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================================================
# DECORATORS
# ============================================================================

def audit_log(action, resource_type, resource_id=None):
    """Decorator to log actions to audit trail"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                result = f(*args, **kwargs)
                
                # Log successful action
                log = AuditLog(
                    user_id=get_jwt_identity() if request.method != 'GET' else None,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', ''),
                    status='success',
                    details={'method': request.method, 'endpoint': request.path}
                )
                db.session.add(log)
                db.session.commit()
                
                audit_logger.info(
                    f"Action: {action} | Resource: {resource_type} | "
                    f"User: {get_jwt_identity()} | Status: success"
                )
                
                return result
            except Exception as e:
                audit_logger.error(
                    f"Action: {action} | Resource: {resource_type} | Error: {str(e)}"
                )
                raise
        
        return decorated_function
    return decorator


def role_required(roles):
    """Decorator to check user role"""
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or user.role not in roles:
                audit_logger.warning(
                    f"Unauthorized access attempt by user {user_id} "
                    f"to resource requiring roles: {roles}"
                )
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def check_file_extension(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    app_logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit errors"""
    audit_logger.warning(f"Rate limit exceeded for {request.remote_addr}")
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    """User registration endpoint"""
    data = request.get_json()
    
    # Validation
    if not all(k in data for k in ['username', 'email', 'password', 'full_name']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 409
    
    # Create user
    user = User(
        username=data['username'],
        email=data['email'],
        full_name=data['full_name'],
        role='user'
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    audit_logger.info(f"New user registered: {user.username}")
    
    return jsonify({
        'message': 'User registered successfully',
        'user': user.to_dict()
    }), 201


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    """User login endpoint"""
    data = request.get_json()
    
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user:
        # Log failed attempt
        audit_logger.warning(f"Login attempt for non-existent user: {data['username']}")
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if user is locked
    if user.is_locked:
        return jsonify({'error': 'User account is locked'}), 403
    
    # Check if user is active
    if not user.is_active:
        return jsonify({'error': 'User account is inactive'}), 403
    
    # Verify password
    if not user.check_password(data['password']):
        # Record failed login
        user.failed_login_attempts += 1
        user.last_failed_login = datetime.utcnow()
        
        # Lock account after max attempts
        if user.failed_login_attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
            user.is_locked = True
            audit_logger.warning(f"User account locked: {user.username} (too many failed attempts)")
        
        db.session.commit()
        
        LoginAttempt(
            user_id=user.id,
            ip_address=request.remote_addr,
            success=False
        )
        db.session.add(LoginAttempt.query.first() or LoginAttempt())
        
        audit_logger.warning(f"Failed login attempt for user: {user.username}")
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Successful login
    user.failed_login_attempts = 0
    user.last_login = datetime.utcnow()
    
    LoginAttempt(
        user_id=user.id,
        ip_address=request.remote_addr,
        success=True
    )
    
    db.session.commit()
    
    # Generate tokens
    access_token = create_access_token(
        identity=user.id,
        additional_claims={'role': user.role}
    )
    
    audit_logger.info(f"User logged in successfully: {user.username}")
    
    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'user': user.to_dict(),
        'requires_2fa': user.two_fa_enabled
    }), 200


@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout endpoint"""
    user_id = get_jwt_identity()
    audit_logger.info(f"User logged out: {user_id}")
    
    return jsonify({'message': 'Logout successful'}), 200


# ============================================================================
# USER MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Get user details"""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Check authorization
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if current_user_id != user_id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    audit_logger.info(f"User profile accessed: {user.username}")
    
    return jsonify(user.to_dict()), 200


@app.route('/api/users/<int:user_id>/password', methods=['PUT'])
@jwt_required()
@limiter.limit("5 per hour")
def change_password(user_id):
    """Change user password"""
    current_user_id = get_jwt_identity()
    
    if current_user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    
    if not data.get('old_password') or not data.get('new_password'):
        return jsonify({'error': 'Missing required fields'}), 400
    
    user = User.query.get(user_id)
    
    if not user.check_password(data['old_password']):
        return jsonify({'error': 'Invalid current password'}), 401
    
    try:
        user.set_password(data['new_password'])
        db.session.commit()
        
        audit_logger.info(f"Password changed for user: {user.username}")
        
        return jsonify({'message': 'Password changed successfully'}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/users', methods=['GET'])
@role_required(['admin'])
def list_users():
    """List all users (admin only)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    paginated = User.query.paginate(page=page, per_page=per_page)
    
    return jsonify({
        'users': [u.to_dict() for u in paginated.items],
        'total': paginated.total,
        'pages': paginated.pages,
        'current_page': page
    }), 200


# ============================================================================
# DOCUMENT MANAGEMENT ENDPOINTS
# ============================================================================

@app.route('/api/documents', methods=['POST'])
@jwt_required()
@audit_log('DOCUMENT_UPLOAD', 'document')
def upload_document():
    """Upload a new document"""
    user_id = get_jwt_identity()
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not check_file_extension(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    # Read file content
    file_content = file.read()
    
    # Check file size
    if len(file_content) > app.config['MAX_FILE_SIZE']:
        return jsonify({'error': 'File size exceeds maximum allowed'}), 413
    
    # Calculate file hash
    file_hash = hashlib.sha256(file_content).hexdigest()
    
    # Check if duplicate
    existing = Document.query.filter_by(file_hash=file_hash).first()
    if existing:
        return jsonify({'error': 'Duplicate file detected'}), 409
    
    # Save file
    filename = f"{secrets.token_hex(8)}_{file.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Encrypt file if enabled
    if app.config.get('ENCRYPT_FILES', True):
        encrypted_content = cipher_suite.encrypt(file_content)
        with open(file_path, 'wb') as f:
            f.write(encrypted_content)
    else:
        with open(file_path, 'wb') as f:
            f.write(file_content)
    
    # Create document record
    data = request.form.to_dict()
    
    document = Document(
        title=data.get('title', file.filename),
        description=data.get('description', ''),
        document_type=data.get('document_type', 'other'),
        file_path=file_path,
        file_hash=file_hash,
        file_size=len(file_content),
        user_id=user_id,
        subject_id=data.get('subject_id'),
        subject_name=data.get('subject_name'),
        issuing_authority=data.get('issuing_authority'),
        access_level=data.get('access_level', 'confidential'),
        is_encrypted=True
    )
    
    if data.get('issue_date'):
        document.issue_date = datetime.fromisoformat(data['issue_date'])
    
    if data.get('expiry_date'):
        document.expiry_date = datetime.fromisoformat(data['expiry_date'])
    
    db.session.add(document)
    db.session.commit()
    
    app_logger.info(f"Document uploaded by user {user_id}: {document.id}")
    
    return jsonify({
        'message': 'Document uploaded successfully',
        'document': document.to_dict()
    }), 201


@app.route('/api/documents/<int:document_id>', methods=['GET'])
@jwt_required()
def get_document(document_id):
    """Get document metadata"""
    user_id = get_jwt_identity()
    document = Document.query.get(document_id)
    
    if not document:
        return jsonify({'error': 'Document not found'}), 404
    
    # Check authorization
    user = User.query.get(user_id)
    if document.user_id != user_id and user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Log access
    AccessLog(
        document_id=document_id,
        user_id=user_id,
        access_type='view',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')
    )
    db.session.commit()
    
    return jsonify(document.to_dict()), 200


@app.route('/api/documents/<int:document_id>/download', methods=['GET'])
@jwt_required()
def download_document(document_id):
    """Download a document"""
    user_id = get_jwt_identity()
    document = Document.query.get(document_id)
    
    if not document:
        return jsonify({'error': 'Document not found'}), 404
    
    # Check authorization
    user = User.query.get(user_id)
    if document.user_id != user_id and user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Read and decrypt file
    try:
        with open(document.file_path, 'rb') as f:
            file_content = f.read()
        
        if document.is_encrypted:
            file_content = cipher_suite.decrypt(file_content)
        
        # Log access
        AccessLog(
            document_id=document_id,
            user_id=user_id,
            access_type='download',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        db.session.commit()
        
        response = make_response(file_content)
        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Content-Disposition'] = f'attachment; filename={document.title}'
        
        app_logger.info(f"Document downloaded by user {user_id}: {document_id}")
        
        return response
    
    except Exception as e:
        app_logger.error(f"Error downloading document: {str(e)}")
        return jsonify({'error': 'Error downloading document'}), 500


@app.route('/api/documents/<int:document_id>', methods=['PUT'])
@jwt_required()
@audit_log('DOCUMENT_UPDATE', 'document')
def update_document(document_id):
    """Update document metadata"""
    user_id = get_jwt_identity()
    document = Document.query.get(document_id)
    
    if not document:
        return jsonify({'error': 'Document not found'}), 404
    
    # Check authorization
    user = User.query.get(user_id)
    if document.user_id != user_id and user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    
    # Update allowed fields
    if 'title' in data:
        document.title = data['title']
    if 'description' in data:
        document.description = data['description']
    if 'status' in data:
        document.status = data['status']
    if 'access_level' in data:
        document.access_level = data['access_level']
    
    document.updated_at = datetime.utcnow()
    db.session.commit()
    
    app_logger.info(f"Document updated by user {user_id}: {document_id}")
    
    return jsonify({
        'message': 'Document updated successfully',
        'document': document.to_dict()
    }), 200


@app.route('/api/documents/<int:document_id>', methods=['DELETE'])
@jwt_required()
@audit_log('DOCUMENT_DELETE', 'document')
def delete_document(document_id):
    """Delete a document"""
    user_id = get_jwt_identity()
    document = Document.query.get(document_id)
    
    if not document:
        return jsonify({'error': 'Document not found'}), 404
    
    # Check authorization
    user = User.query.get(user_id)
    if document.user_id != user_id and user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Delete file
    try:
        if os.path.exists(document.file_path):
            os.remove(document.file_path)
    except Exception as e:
        app_logger.error(f"Error deleting file: {str(e)}")
    
    # Delete document record
    db.session.delete(document)
    db.session.commit()
    
    app_logger.info(f"Document deleted by user {user_id}: {document_id}")
    
    return jsonify({'message': 'Document deleted successfully'}), 200


@app.route('/api/documents', methods=['GET'])
@jwt_required()
def list_documents():
    """List user's documents"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status', None)
    
    query = Document.query
    
    # Filter by ownership or admin access
    if user.role != 'admin':
        query = query.filter_by(user_id=user_id)
    
    if status:
        query = query.filter_by(status=status)
    
    paginated = query.paginate(page=page, per_page=per_page)
    
    return jsonify({
        'documents': [d.to_dict() for d in paginated.items],
        'total': paginated.total,
        'pages': paginated.pages,
        'current_page': page
    }), 200


# ============================================================================
# PDF GENERATION ENDPOINTS
# ============================================================================

@app.route('/api/documents/<int:document_id>/export-pdf', methods=['GET'])
@jwt_required()
def export_document_pdf(document_id):
    """Export document metadata as PDF certificate"""
    user_id = get_jwt_identity()
    document = Document.query.get(document_id)
    
    if not document:
        return jsonify({'error': 'Document not found'}), 404
    
    # Check authorization
    user = User.query.get(user_id)
    if document.user_id != user_id and user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Create PDF in memory
        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        # Prepare content
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f4788'),
            spaceAfter=30,
            alignment=1  # Center
        )
        
        elements.append(Paragraph('RENAPER DOCUMENT CERTIFICATE', title_style))
        elements.append(Spacer(1, 0.3*inch))
        
        # Document details table
        data = [
            ['Field', 'Value'],
            ['Title', document.title],
            ['Document Type', document.document_type],
            ['Subject', document.subject_name or 'N/A'],
            ['Subject ID', document.subject_id or 'N/A'],
            ['Issuing Authority', document.issuing_authority or 'N/A'],
            ['Issue Date', document.issue_date.strftime('%Y-%m-%d') if document.issue_date else 'N/A'],
            ['Expiry Date', document.expiry_date.strftime('%Y-%m-%d') if document.expiry_date else 'N/A'],
            ['Status', document.status.upper()],
            ['Access Level', document.access_level.upper()],
            ['File Hash (SHA-256)', document.file_hash[:32] + '...'],
            ['Uploaded By', document.owner.full_name],
            ['Upload Date', document.created_at.strftime('%Y-%m-%d %H:%M:%S')],
        ]
        
        table = Table(data, colWidths=[2*inch, 3.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4788')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ]))
        
        elements.append(table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Footer
        footer_style = ParagraphStyle(
            'FooterStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.grey,
            alignment=1
        )
        
        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph(
            f'Document ID: {document.id} | Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}',
            footer_style
        ))
        elements.append(Paragraph(
            'This is an official RENAPER system document certification.',
            footer_style
        ))
        
        # Build PDF
        doc.build(elements)
        
        pdf_buffer.seek(0)
        
        # Log access
        AccessLog(
            document_id=document_id,
            user_id=user_id,
            access_type='print',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        db.session.commit()
        
        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=document_{document_id}_certificate.pdf'
        
        app_logger.info(f"PDF exported by user {user_id}: {document_id}")
        
        return response
    
    except Exception as e:
        app_logger.error(f"Error generating PDF: {str(e)}")
        return jsonify({'error': 'Error generating PDF'}), 500


# ============================================================================
# AUDIT LOG ENDPOINTS
# ============================================================================

@app.route('/api/audit-logs', methods=['GET'])
@role_required(['admin'])
def get_audit_logs():
    """Get audit logs (admin only)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    action = request.args.get('action', None)
    user_id = request.args.get('user_id', None, type=int)
    
    query = AuditLog.query
    
    if action:
        query = query.filter_by(action=action)
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    paginated = query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=per_page)
    
    return jsonify({
        'logs': [log.to_dict() for log in paginated.items],
        'total': paginated.total,
        'pages': paginated.pages,
        'current_page': page
    }), 200


@app.route('/api/documents/<int:document_id>/access-logs', methods=['GET'])
@jwt_required()
def get_document_access_logs(document_id):
    """Get access logs for a document"""
    user_id = get_jwt_identity()
    document = Document.query.get(document_id)
    
    if not document:
        return jsonify({'error': 'Document not found'}), 404
    
    # Check authorization
    user = User.query.get(user_id)
    if document.user_id != user_id and user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    logs = AccessLog.query.filter_by(document_id=document_id).all()
    
    return jsonify({
        'logs': [
            {
                'id': log.id,
                'user_id': log.user_id,
                'access_type': log.access_type,
                'ip_address': log.ip_address,
                'created_at': log.created_at.isoformat()
            }
            for log in logs
        ]
    }), 200


# ============================================================================
# HEALTH & STATISTICS ENDPOINTS
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@app.route('/api/stats', methods=['GET'])
@role_required(['admin'])
def get_statistics():
    """Get system statistics (admin only)"""
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_documents = Document.query.count()
    total_audit_logs = AuditLog.query.count()
    
    # Documents by type
    docs_by_type = db.session.query(
        Document.document_type,
        db.func.count(Document.id)
    ).group_by(Document.document_type).all()
    
    return jsonify({
        'total_users': total_users,
        'active_users': active_users,
        'locked_users': User.query.filter_by(is_locked=True).count(),
        'total_documents': total_documents,
        'total_audit_logs': total_audit_logs,
        'documents_by_type': {dtype: count for dtype, count in docs_by_type},
        'timestamp': datetime.utcnow().isoformat()
    }), 200


# ============================================================================
# SEARCH ENDPOINT
# ============================================================================

@app.route('/api/search', methods=['GET'])
@jwt_required()
def search():
    """Search documents"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    query_str = request.args.get('q', '').strip()
    doc_type = request.args.get('type', None)
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    if not query_str:
        return jsonify({'error': 'Search query required'}), 400
    
    # Build search query
    search_query = Document.query
    
    if user.role != 'admin':
        search_query = search_query.filter_by(user_id=user_id)
    
    # Search by title, description, subject_name
    search_query = search_query.filter(
        db.or_(
            Document.title.ilike(f'%{query_str}%'),
            Document.description.ilike(f'%{query_str}%'),
            Document.subject_name.ilike(f'%{query_str}%'),
            Document.subject_id.ilike(f'%{query_str}%')
        )
    )
    
    if doc_type:
        search_query = search_query.filter_by(document_type=doc_type)
    
    paginated = search_query.paginate(page=page, per_page=per_page)
    
    return jsonify({
        'results': [d.to_dict() for d in paginated.items],
        'total': paginated.total,
        'pages': paginated.pages,
        'current_page': page
    }), 200


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def initialize_database():
    """Initialize database with tables"""
    with app.app_context():
        db.create_all()
        
        # Create default admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@renaper.gov.ar',
                full_name='System Administrator',
                role='admin',
                is_active=True
            )
            admin.set_password('AdminPassword123!')
            db.session.add(admin)
            db.session.commit()
            
            app_logger.info("Default admin user created")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == '__main__':
    initialize_database()
    
    app.run(
        host=os.environ.get('FLASK_HOST', '0.0.0.0'),
        port=int(os.environ.get('FLASK_PORT', 5000)),
        debug=os.environ.get('FLASK_ENV') == 'development'
    )
