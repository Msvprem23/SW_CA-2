from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
#CSRF Token
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf'}

# Utility Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def role_required(role):
    def decorator(func):
        def wrapper(*args, **kwargs):
            app.logger.info(f"Checking role for session: {session}")
            if 'role' in session and session['role'] == role:
                return func(*args, **kwargs)
            flash('Access denied!')
            return redirect(url_for('home'))
        wrapper.__name__ = f"{func.__name__}_{role}"  # Ensure unique function name
        return wrapper
    return decorator

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    description = db.Column(db.String(200), nullable=True)
    file_path = db.Column(db.String(200), nullable=True)

# Routes
@app.route('/')
def home():
    return render_template('index.html')
#Password Management security
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!')
            return redirect(url_for('login'))
        except Exception as e:
            app.logger.error(f"Registration error: {e}")
            flash('User already exists or error occurred.')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            flash('Login successful!')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!')
    return redirect(url_for('home'))

@app.route('/admin', endpoint='admin_dashboard')
@role_required('admin')
def admin_dashboard():
    items = Item.query.all()
    return render_template('admin_dashboard.html', items=items)

@app.route('/user', endpoint='user_dashboard')
@role_required('user')
def user_dashboard():
    items = Item.query.all()
    return render_template('user_dashboard.html', items=items)

#File Upload Security
@app.route('/add_item', methods=['GET', 'POST'])
@role_required('admin')
def add_item():
    if request.method == 'POST':
        # Validate mandatory fields
        name = request.form.get('name')
        description = request.form.get('description')
        if not name or not description:
            flash('Name and description are required!')
            return redirect(url_for('add_item'))

        # Handle optional file upload
        file = request.files.get('file')
        file_path = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            app.logger.info(f"File saved: {file_path}")
        elif file:
            flash('Invalid file type! Please upload a valid file.')
            return redirect(url_for('add_item'))

        # Save the item to the database
        new_item = Item(name=name, description=description, file_path=file_path)
        db.session.add(new_item)
        db.session.commit()
        flash('Item added successfully!')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_item.html')


@app.route('/upload', methods=['POST'])
@role_required('admin')  # Only admins can upload standalone files
def upload_file():
    file = request.files.get('file')
    if not file or not allowed_file(file.filename):
        flash('Invalid or missing file!')
        return redirect(url_for('admin_dashboard'))

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    flash('File uploaded successfully!')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_item/<int:item_id>', methods=['POST'], endpoint='delete_item')
@role_required('admin')
def delete_item(item_id):
    item = Item.query.get(item_id)
    if item:
        if item.file_path and os.path.exists(item.file_path):
            os.remove(item.file_path)
        db.session.delete(item)
        db.session.commit()
        flash('Item deleted successfully!')
    else:
        flash('Item not found')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'], endpoint='edit_item')
@role_required('admin')
def edit_item(item_id):
    item = Item.query.get(item_id)
    if not item:
        flash('Item not found')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        item.name = request.form.get('name')
        item.description = request.form.get('description')
        db.session.commit()
        flash('Item updated successfully!')
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_item.html', item=item)

@app.route('/download/<int:item_id>', endpoint='download_file')
def download_file(item_id):
    if 'role' in session:
        item = Item.query.get(item_id)
        if item and os.path.isfile(item.file_path):
            return send_from_directory(app.config['UPLOAD_FOLDER'], os.path.basename(item.file_path), as_attachment=True)
    flash('File not found or access denied!')
    return redirect(url_for('user_dashboard'))

@app.route('/clear_session')
def clear_session():
    session.clear()
    flash('Session cleared!')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
