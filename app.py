from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'
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

# User Registration (Admin Only)
@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if not current_user.is_admin:
        return "Access Denied", 403
    if request.method == 'POST':
        username = request.form['username']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Choose a different one.', 'danger')
            return redirect(url_for('register'))
        
        password = generate_password_hash(request.form['password'])
        is_admin = True if request.form.get('is_admin') else False
        new_user = User(username=username, password=password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('register.html')

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
        new_user = User(username=username, password=password, is_admin=False)  # Normal user
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
        flash('Invalid credentials')
    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# User Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        current_user.data = request.form['data']
        db.session.commit()
    return render_template('dashboard.html')

# Admin Panel
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return "Access Denied", 403

    search_query = request.args.get('search', '')
    role_filter = request.args.get('role', '')

    users = User.query
    if search_query:
        users = users.filter(User.username.contains(search_query))
    if role_filter == 'admin':
        users = users.filter(User.is_admin == True)
    elif role_filter == 'user':
        users = users.filter(User.is_admin == False)

    users = users.all()
    return render_template('admin.html', users=users)

# Edit User (Admin Only)
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.data = request.form['data']
        db.session.commit()
        return redirect(url_for('admin'))
    return render_template('edit_user.html', user=user)

# Delete User (Admin Only)
@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin'))

# Reset User Password (Admin Only)
@app.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def reset_password(user_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash(f"Password for {user.username} has been reset.", 'success')
        return redirect(url_for('admin'))
    
    return render_template('reset_password.html', user=user)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_default_admin()
    app.run(debug=True)

