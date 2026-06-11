import os
import sqlite3
from flask import Flask, render_template, request, flash, redirect, url_for, send_file, session
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'cyberforensics_secure_session_token_key'

# Application Directory Configurations
UPLOAD_FOLDER = 'uploads'
DATABASE_FILE = 'forensics_workspace.db'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_database():
    """Initializes the database schema including the updated security policy trackers."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Core Users Table tracking usernames, passwords, and consecutive login failures
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0
        )
    ''')
    
    # Case Management Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            case_name TEXT NOT NULL,
            suspect_name TEXT,
            investigator TEXT NOT NULL
        )
    ''')
    
    # Artifact Tracking Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            filename TEXT NOT NULL,
            filesize INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(case_id) REFERENCES cases(case_id)
        )
    ''')
    
    conn.commit()
    conn.close()

init_database()


# =========================================================================
# CRYPTOGRAPHIC PROCESSING ENGINES
# =========================================================================

def transform_image_bytes(file_bytes, pin):
    """Applies a symmetrical XOR stream cipher using a key derived from the 4-digit PIN."""
    pin_int = int(pin)
    pin_seed = sum(int(char) for char in str(pin)) + pin_int
    byte_array = bytearray(file_bytes)
    xor_key = (pin_seed % 254) + 1
    
    for i in range(len(byte_array)):
        byte_array[i] ^= xor_key
        
    return bytes(byte_array)


# =========================================================================
# REGISTRATION & AUTHENTICATION PROTOCOLS
# =========================================================================

@app.route('/')
def root_gate():
    if 'user' in session:
        return redirect(url_for('dashboard_view'))
    return redirect(url_for('login_node'))


@app.route('/register', methods=['POST'])
def register_node():
    """Handles new analyst registration accounts."""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    if not username or not password:
        flash("Registration Error: All credential fields are mandatory.", "danger")
        return redirect(url_for('login_node'))
        
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO users (username, password, failed_attempts) VALUES (?, ?, 0)", (username, password))
        conn.commit()
        flash(f"Account '{username}' successfully registered! You can now log in.", "success")
    except sqlite3.IntegrityError:
        flash("Registration Conflict: This username is already taken.", "danger")
    finally:
        conn.close()
        
    return redirect(url_for('login_node'))


@app.route('/login', methods=['GET', 'POST'])
def login_node():
    """Validates user sessions and enforces the 3-strike account destruction policy."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Look for the user profile
        cursor.execute("SELECT password, failed_attempts FROM users WHERE username = ?", (username,))
        user_record = cursor.fetchone()
        
        if not user_record:
            flash("Authentication Failure: Access denied.", "danger")
            conn.close()
            return redirect(url_for('login_node'))
            
        correct_password, current_failures = user_record
        
        # Scenario A: Password matches perfectly
        if password == correct_password:
            # Reset counters on success
            cursor.execute("UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
            conn.commit()
            conn.close()
            session['user'] = username
            flash(f"Authorized session opened for analyst '{username}'.", "success")
            return redirect(url_for('dashboard_view'))
            
        # Scenario B: Password mismatch
        else:
            new_failures = current_failures + 1
            
            if new_failures >= 3:
                # Target Destruction Action: Purge user profile permanently
                cursor.execute("DELETE FROM users WHERE username = ?", (username,))
                conn.commit()
                conn.close()
                flash(f"SECURITY ALERT: Account '{username}' hit 3 failed login attempts and has been permanently deleted.", "danger")
            else:
                cursor.execute("UPDATE users SET failed_attempts = ? WHERE username = ?", (new_failures, username))
                conn.commit()
                conn.close()
                remaining = 3 - new_failures
                flash(f"Warning: Incorrect password. You have {remaining} attempt(s) left before permanent deletion.", "danger")
                
            return redirect(url_for('login_node'))
            
    return render_template('login.html')


@app.route('/logout')
def logout_node():
    session.pop('user', None)
    flash("Session Terminated safely.", "info")
    return redirect(url_for('login_node'))


# =========================================================================
# SYSTEM APPLICATION ROUTES
# =========================================================================

@app.route('/dashboard')
def dashboard_view():
    if 'user' not in session:
        return redirect(url_for('login_node'))
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cases")
        total_cases = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM artifacts")
        total_artifacts = cursor.fetchone()[0]
        conn.close()
    except Exception:
        total_cases, total_artifacts = 0, 0
    return render_template('dashboard.html', total_cases=total_cases, total_artifacts=total_artifacts)

@app.route('/case-manager', methods=['GET', 'POST'])
def case_manager():
    if 'user' not in session: return redirect(url_for('login_node'))
    if request.method == 'POST':
        case_id = request.form.get('case_id')
        case_name = request.form.get('case_name')
        suspect = request.form.get('suspect_name')
        investigator = request.form.get('investigator_name')
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO cases (case_id, case_name, suspect_name, investigator) VALUES (?, ?, ?, ?)", (case_id, case_name, suspect, investigator))
            conn.commit()
            conn.close()
            flash(f"Success: Case {case_id} registered.", "success")
        except sqlite3.IntegrityError:
            flash("Database Conflict: Case ID already exists.", "danger")
    return redirect(url_for('dashboard_view'))

@app.route('/evidence-collector', methods=['GET', 'POST'])
def evidence_collector():
    if 'user' not in session: return redirect(url_for('login_node'))
    if request.method == 'POST':
        case_id = request.form.get('case_id')
        file = request.files.get('evidence_file')
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(save_path)
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO artifacts (case_id, filename, filesize) VALUES (?, ?, ?)", (case_id, filename, os.path.getsize(save_path)))
            conn.commit()
            conn.close()
            flash(f"Artifact successfully bound to Case ID: {case_id}", "success")
    return redirect(url_for('dashboard_view'))

@app.route('/threat-scanner', methods=['GET', 'POST'])
def threat_scanner():
    if 'user' not in session: return redirect(url_for('login_node'))
    # Remained operational for matching prior layouts...
    return redirect(url_for('dashboard_view'))

@app.route('/timeline-parser', methods=['GET', 'POST'])
def timeline_parser():
    if 'user' not in session: return redirect(url_for('login_node'))
    return redirect(url_for('dashboard_view'))

@app.route('/image-crypto', methods=['GET', 'POST'])
def image_crypto():
    if 'user' not in session:
        return redirect(url_for('login_node'))
    if request.method == 'POST':
        action = request.form.get('action')  
        pin = request.form.get('pin')
        file = request.files.get('image_file')
        if not file or not pin or len(pin) != 4 or not pin.isdigit():
            flash("Execution Error: Check your input values.", "danger")
            return redirect(request.url)
        input_bytes = file.read()
        processed_bytes = transform_image_bytes(input_bytes, pin)
        out_filename = f"processed_{file.filename}"
        out_path = os.path.join(UPLOAD_FOLDER, out_filename)
        with open(out_path, 'wb') as f:
            f.write(processed_bytes)
        return send_file(out_path, as_attachment=True, download_name=out_filename)
    return render_template('image_crypto.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)