from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Initialize Flask App
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Moved to the correct place
app.config['UPLOAD_FOLDER'] = 'uploads'  # Folder to store uploaded files
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    data = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(100), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create Default Admin
def create_default_admin():
    admin = User.query.filter_by(username="Admin").first()
    if not admin:
        admin = User(username="Admin", password=generate_password_hash("IIUMChessClub"), is_admin=True)
        db.session.add(admin)
        db.session.commit()

# Home Route
@app.route('/')
def home():
    return redirect(url_for('login'))

# Public User Registration
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Choose a different one.', 'danger')
            return redirect(url_for('signup'))

        password = generate_password_hash(request.form['password'])
        new_user = User(username=username, password=password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('admin' if user.is_admin else 'dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# User Dashboard (with form fields and file upload)
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        current_user.data = request.form['data']

        # Handle File Upload
        if 'file' in request.files:
            file = request.files['file']
            if file.filename:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(file_path)
                current_user.file_path = file.filename  # Save only filename, not full path

        db.session.commit()
        flash('Data saved successfully!', 'success')
    
    return render_template('dashboard.html', user=current_user)

# Admin Panel (Now properly filtering users)
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return "Access Denied", 403

    search_query = request.args.get('search', '')
    role_filter = request.args.get('role', '')

    users = User.query
    if search_query:
        users = users.
