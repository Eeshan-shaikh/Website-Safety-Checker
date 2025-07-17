import os
import re
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import sqlite3
from urllib.parse import urlparse
import models
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
    
    # Initialize URL categories
    try:
        import init_categories
    except Exception as e:
        print(f"Error initializing categories: {e}")

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
    
    # Check for URL parameter in GET request (for re-checking URLs from history)
    if request.method == 'GET' and request.args.get('url'):
        url_to_check = request.args.get('url')
        if url_to_check:
            # Normalize URL if needed
            if not re.match(r'^https?:\/\/', url_to_check):
                url_to_check = 'http://' + url_to_check
            
            features = extract_features(url_to_check)
            prediction = URLSafetyModel.predict(features)
            # Save history
            conn = get_db_connection()
            is_safe_int = 1 if prediction else 0
            conn.execute(
                'INSERT INTO url_checks (user_id, url, is_safe) VALUES (?, ?, ?)',
                (session['user_id'], url_to_check, is_safe_int)
            )
            conn.commit()
            conn.close()
            details = URLSafetyModel.get_explanation(features)
            
            # Add the "uses_https" feature to details
            parse_result = urlparse(url_to_check)
            details['uses_https'] = parse_result.scheme == 'https'
    
    # Handle POST requests
    elif request.method == 'POST':
        # Check if it's a bulk URL check
        if 'bulk_urls' in request.form:
            bulk_urls = request.form['bulk_urls'].strip().split('\n')
            if not bulk_urls or all(not url.strip() for url in bulk_urls):
                flash("Please enter at least one URL", 'danger')
            else:
                results = []
                conn = get_db_connection()
                for url in bulk_urls:
                    url = url.strip()
                    if not url:
                        continue
                    # Normalize URL
                    if not re.match(r'^https?:\/\/', url):
                        url = 'http://' + url
                    features = extract_features(url)
                    is_safe = URLSafetyModel.predict(features)
                    # Save history
                    is_safe_int = 1 if is_safe else 0
                    conn.execute(
                        'INSERT INTO url_checks (user_id, url, is_safe) VALUES (?, ?, ?)',
                        (session['user_id'], url, is_safe_int)
                    )
                    # Get reputation scores
                    reputation_score = models.additional_features.get('reputation_score', 0)
                    threat_level = models.additional_features.get('threat_level', 'Unknown')
                    results.append({
                        'url': url,
                        'is_safe': is_safe,
                        'reputation_score': reputation_score,
                        'threat_level': threat_level
                    })
                conn.commit()
                conn.close()
                return render_template('bulk_results.html', results=results)
        else:
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
                
                # Add the "uses_https" feature to details
                parse_result = urlparse(url_to_check)
                details['uses_https'] = parse_result.scheme == 'https'
    
    # Get user history
    conn = get_db_connection()
    history = conn.execute(
        'SELECT url, is_safe, checked_at FROM url_checks WHERE user_id = ? ORDER BY checked_at DESC LIMIT 10',
        (session['user_id'],)
    ).fetchall()
    
    # Get statistics for data visualization
    stats = {
        'total_checks': conn.execute('SELECT COUNT(*) FROM url_checks WHERE user_id = ?', 
                                    (session['user_id'],)).fetchone()[0],
        'safe_count': conn.execute('SELECT COUNT(*) FROM url_checks WHERE user_id = ? AND is_safe = 1', 
                                  (session['user_id'],)).fetchone()[0],
        'unsafe_count': conn.execute('SELECT COUNT(*) FROM url_checks WHERE user_id = ? AND is_safe = 0', 
                                    (session['user_id'],)).fetchone()[0]
    }
    conn.close()
    
    return render_template('dashboard.html', prediction=prediction, url=url_to_check, 
                          history=history, details=details, stats=stats)

@app.route('/clear-history', methods=['POST'])
def clear_history():
    if 'user_id' not in session:
        flash("Please login to access this feature", 'warning')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM url_checks WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    
    flash("Your URL check history has been cleared", 'success')
    return redirect(url_for('dashboard'))

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'user_id' not in session:
        flash("Please login to submit feedback", 'warning')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        # Handle the feedback form submission
        email = request.form.get('email', '')
        feedback_type = request.form.get('feedback_type', 'general')
        message = request.form.get('message', '')
        url = request.form.get('url', '')
        
        # Store the feedback in the database
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO user_feedback (user_id, email, feedback_type, message, url) VALUES (?, ?, ?, ?, ?)',
            (session['user_id'], email, feedback_type, message, url)
        )
        conn.commit()
        conn.close()
        
        flash('Thank you for your feedback! We appreciate your input.', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('feedback.html')

# API for developers
@app.route('/api/v1/check', methods=['POST'])
def api_check_url():
    # Check for API key in the request
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return {'error': 'API key is required'}, 401
    
    # Validate API key
    conn = get_db_connection()
    api_user = conn.execute('SELECT user_id FROM api_keys WHERE api_key = ?', (api_key,)).fetchone()
    conn.close()
    
    if not api_user:
        return {'error': 'Invalid API key'}, 401
    
    # Get URL from request
    data = request.get_json()
    if not data or 'url' not in data:
        return {'error': 'URL is required'}, 400
    
    url = data['url']
    
    # Normalize URL
    if not re.match(r'^https?:\/\/', url):
        url = 'http://' + url
    
    # Extract features and predict
    features = extract_features(url)
    prediction = URLSafetyModel.predict(features)
    
    # Get explanation data
    details = URLSafetyModel.get_explanation(features)
    
    # Add the "uses_https" feature to details
    parse_result = urlparse(url)
    details['uses_https'] = parse_result.scheme == 'https'
    
    # Get reputation scores from additional_features
    reputation_score = models.additional_features.get('reputation_score', 0)
    threat_level = models.additional_features.get('threat_level', 'Unknown')
    
    # Save record of API check
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO url_checks (user_id, url, is_safe, api_request) VALUES (?, ?, ?, ?)',
        (api_user['user_id'], url, 1 if prediction else 0, 1)
    )
    conn.commit()
    conn.close()
    
    # Return JSON response
    response = {
        'url': url,
        'is_safe': bool(prediction),
        'reputation_score': reputation_score,
        'threat_level': threat_level,
        'analysis': {
            'url_length': details['url_length'],
            'has_ip': details['has_ip'],
            'dot_count': details['dot_count'],
            'hyphen_count': details['hyphen_count'],
            'at_count': details['at_count'],
            'question_mark_count': details['question_mark_count'],
            'equal_sign_count': details['equal_sign_count'],
            'uses_https': details['uses_https']
        },
        'threats': details['threats'] if 'threats' in details and details['threats'] else []
    }
    
    return response, 200

@app.route('/extension')
def extension_page():
    return render_template('extension.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
