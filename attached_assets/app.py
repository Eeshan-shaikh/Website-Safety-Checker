import os
import re
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import sqlite3
from urllib.parse import urlparse
from models import URLSafetyModel, extract_features

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24))
# Needed for url_for to generate with https
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

DATABASE = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(DATABASE):
        conn = get_db_connection()
        with app.open_resource('schema.sql', mode='r') as f:
            conn.executescript(f.read())
        conn.commit()
        conn.close()

# Call initialization explicitly before the first request or app run
def initialize():
    init_db()
    URLSafetyModel.load_model()

initialize()

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash("Passwords do not match", 'danger')
            return render_template('register.html')
        if len(username) < 3 or len(password) < 5:
            flash("Username must be at least 3 characters and password at least 5 characters", 'danger')
            return render_template('register.html')
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash("Username already taken", 'danger')
            conn.close()
            return render_template('register.html')
        password_hash = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()
        flash("Registration successful! Please login.", 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", 'info')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash("Please login to access dashboard", 'warning')
        return redirect(url_for('login'))
    prediction = None
    url_to_check = None
    details = None
    if request.method == 'POST':
        url_to_check = request.form['url']
        if not url_to_check:
            flash("Please enter a URL", 'danger')
        else:
            # Normalize URL
            if not re.match(r'^https?:\/\/', url_to_check):
                url_to_check = 'http://' + url_to_check
            features = extract_features(url_to_check)
            prediction = URLSafetyModel.predict(features)
            # Save history
            conn = get_db_connection()
            # Convert the prediction to an integer (1 for True, 0 for False)
            is_safe_int = 1 if prediction else 0
            conn.execute(
                'INSERT INTO url_checks (user_id, url, is_safe) VALUES (?, ?, ?)',
                (session['user_id'], url_to_check, is_safe_int)
            )
            conn.commit()
            conn.close()
            details = URLSafetyModel.get_explanation(features)
    conn = get_db_connection()
    history = conn.execute(
        'SELECT url, is_safe, checked_at FROM url_checks WHERE user_id = ? ORDER BY checked_at DESC LIMIT 10',
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('dashboard.html', prediction=prediction, url=url_to_check, history=history, details=details)

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        # Handle the feedback form submission
        email = request.form.get('email')
        message = request.form.get('message')
        # Process the feedback (e.g., save to database, send email, etc.)
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('dashboard'))  # Redirect to the dashboard or another page
    return render_template('feedback.html')  # Render the feedback form template


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
