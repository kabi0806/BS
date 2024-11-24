from flask import Flask, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = "b'5Eb\x9ch\x1c\x8f\xe4\xb6\xe5\xb4\xf4\xea`\x94T\x07.\x04\x99\xd1\xba\xe6\x83'"

# Database connection
def get_db_connection():
    conn = sqlite3.connect('vulnerabilities.db')
    conn.row_factory = sqlite3.Row
    return conn

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Insecure Direct Object References (IDOR)
@app.route('/profile/<username>')
def profile(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user is None:
        return 'User not found!', 404
    return f'Welcome, {user["username"]}!'

# SQL Injection
@app.route('/search', methods=['POST'])
def search():
    search_query = request.form['search_query']
    conn = get_db_connection()
    results = conn.execute(f'SELECT * FROM items WHERE name LIKE "%{search_query}%"').fetchall()
    conn.close()
    return render_template('search_results.html', results=results)

# Cross-Site Scripting (XSS)
@app.route('/comments', methods=['POST'])
def comments():
    comment = request.form['comment']
    return f'Your comment: {comment}'

# Cross-Site Request Forgery (CSRF)
@app.route('/csrf-form', methods=['GET', 'POST'])
def csrf_form():
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if csrf_token != session.get('csrf_token'):
            return 'CSRF token mismatch!', 403
        return 'Form submitted successfully!'
    session['csrf_token'] = 'random_csrf_token'
    return render_template('csrf_form.html')

# Broken Authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('index'))
        return 'Invalid credentials!', 403
    return render_template('login.html')

# Security Misconfiguration
@app.route('/admin')
def admin():
    return 'Admin panel - insecure!'

# Sensitive Data Exposure
@app.route('/profile-data')
def profile_data():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (session.get('username'),)).fetchone()
    conn.close()
    if user is None:
        return 'User not found!', 404
    return f'Email: {user["email"]}'

# Insufficient Logging & Monitoring
@app.route('/login-attempt', methods=['POST'])
def login_attempt():
    username = request.form['username']
    # Log attempt (insecurely)
    print(f'Login attempt by: {username}')
    return 'Attempt logged!'

# Using Components with Known Vulnerabilities
@app.route('/vulnerable-component')
def vulnerable_component():
    # Example with outdated component
    return 'Using outdated component!'

# Broken Access Control
@app.route('/admin-section')
def admin_section():
    if session.get('username') != 'admin':
        return 'Access denied!', 403
    return 'Admin section'

if __name__ == '__main__':
    app.run(debug=True)
