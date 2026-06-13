import os
import sqlite3
import hashlib
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, send_file, session, jsonify, flash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'cyberforensics_secure_session_token_key'

# Directory & Database Configurations
UPLOAD_FOLDER = 'uploads'
DATABASE_FILE = 'forensics_workspace.db'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Tracks global system-wide inactivity memory state
LAST_GLOBAL_ACTIVITY = datetime.now()

# Known Malicious Signatures Database (SHA-256 Hashes for Testing)
MALWARE_SIGNATURE_DB = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty Executable Layer (Suspicious Null Stream)",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "Web Shell Backdoor Dropper Script",
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824": "Ransomware Cryptolocker Binary Footprint"
}

def init_database():
    """Initializes the database engine schema and sets up tables on boot."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            case_name TEXT NOT NULL,
            suspect_name TEXT,
            investigator TEXT NOT NULL
        )
    ''')
    
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

def wipe_forensic_data():
    """Wipes volatile evidence caches due to extended inactivity (Anti-Forensic Amnesia)."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM artifacts")
        cursor.execute("DELETE FROM cases")
        conn.commit()
        print("[-] AMNESIA TRIGGERED: Ledgers cleared. Accounts preserved.")
    except Exception as e:
        print(f"Error executing amnesia routine: {e}")
    finally:
        conn.close()

# Fire database initialization on application spin-up
init_database()

# =========================================================================
# CENTRAL AUTOMATED SECURITY MONITOR (INACTIVITY & SESSION PROTECTION)
# =========================================================================

@app.before_request
def enforce_security_inactivity_policies():
    """Interceptor that dynamically evaluates user session lifetimes and global amnesia states."""
    global LAST_GLOBAL_ACTIVITY
    now = datetime.now()
    
    # Check for global workstation level inactivity (15 Minutes)
    if (now - LAST_GLOBAL_ACTIVITY) > timedelta(minutes=15):
        wipe_forensic_data()
        
    LAST_GLOBAL_ACTIVITY = now
    
    # Whitelist system gates from auth loops
    if request.endpoint in ['login_node', 'register_node', 'root_gate', 'static'] or not request.endpoint:
        return

    # Check individual user interaction token age (5 Minutes)
    if 'user' in session:
        last_active_string = session.get('last_user_activity')
        if last_active_string:
            last_active_time = datetime.fromisoformat(last_active_string)
            if (now - last_active_time) > timedelta(minutes=5):
                session.clear()
                flash("Security Alert: Session terminated automatically due to inactivity.", "danger")
                return redirect(url_for('login_node'))
        
        session['last_user_activity'] = now.isoformat()
    else:
        return redirect(url_for('login_node'))

# =========================================================================
# ADVANCED STEGANOGRAPHIC CRYPTOGRAPHIC PROCESSING ENGINE
# =========================================================================

def transform_image_bytes(file_bytes, pin, message=""):
    """Applies an XOR stream cipher key generated from a 4-digit PIN sequence."""
    pin_int = int(pin)
    pin_seed = sum(int(char) for char in str(pin)) + pin_int
    xor_key = (pin_seed % 254) + 1
    
    payload_bytes = message.encode('utf-8')
    full_data = bytearray(file_bytes) + b"|VALID_PIN||SECRET|" + payload_bytes
    
    for i in range(len(full_data)):
        full_data[i] ^= xor_key
        
    return bytes(full_data)

# =========================================================================
# SYSTEM OPERATIONS CORE ROUTING GATEWAYS
# =========================================================================

@app.route('/')
def root_gate():
    if 'user' in session: 
        return redirect(url_for('dashboard_view'))
    return redirect(url_for('login_node'))

@app.route('/register', methods=['POST'])
def register_node():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    if not username or not password: 
        flash("Registration failed: Missing parameters.", "danger")
        return redirect(url_for('login_node'))
        
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password, failed_attempts) VALUES (?, ?, 0)", (username, password))
        conn.commit()
        flash("Account created successfully. Authenticate to mount session.", "success")
    except sqlite3.IntegrityError:
        flash("Registration Error: Username token already assigned.", "danger")
    finally: 
        conn.close()
    return redirect(url_for('login_node'))

@app.route('/login', methods=['GET', 'POST'])
def login_node():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT password, failed_attempts FROM users WHERE username = ?", (username,))
        user_record = cursor.fetchone()
        
        if not user_record: 
            flash("Authentication Failure: Invalid credentials.", "danger")
            conn.close()
            return redirect(url_for('login_node'))
            
        correct_password, current_failures = user_record
        
        if password == correct_password:
            cursor.execute("UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
            conn.commit()
            conn.close()
            session['user'] = username
            session['last_user_activity'] = datetime.now().isoformat()
            return redirect(url_for('dashboard_view'))
        else:
            new_failures = current_failures + 1
            if new_failures >= 3:
                cursor.execute("DELETE FROM users WHERE username = ?", (username,))
                flash("🚨 CRITICAL RESPONSE: 3 Failed attempts. Account data purged.", "danger")
            else:
                cursor.execute("UPDATE users SET failed_attempts = ? WHERE username = ?", (new_failures, username))
                flash(f"Authentication Failure. Attempts remaining: {3 - new_failures}", "warning")
            conn.commit()
            conn.close()
            return redirect(url_for('login_node'))
            
    return render_template('login.html')

@app.route('/logout')
def logout_node():
    session.clear()
    return redirect(url_for('login_node'))

@app.route('/dashboard')
def dashboard_view():
    if 'user' not in session:
        return redirect(url_for('login_node'))
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    total_cases = cursor.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    total_artifacts = cursor.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
    
    cases_list = cursor.execute("SELECT case_id, case_name, suspect_name, investigator FROM cases").fetchall()
    artifacts_list = cursor.execute("SELECT case_id, filename, filesize, timestamp FROM artifacts ORDER BY timestamp DESC").fetchall()
    conn.close()
    
    return render_template('dashboard.html', 
                           total_cases=total_cases, 
                           total_artifacts=total_artifacts,
                           cases=cases_list,
                           artifacts=artifacts_list)

@app.route('/case-manager', methods=['POST'])
def case_manager():
    case_id = request.form.get('case_id', '').strip()
    case_name = request.form.get('case_name', '').strip()
    suspect_name = request.form.get('suspect_name', 'Unknown').strip()
    investigator = session.get('user', 'Admin')
    
    if not case_id or not case_name:
        flash("Case Manager: Identification strings cannot be blank.", "warning")
        return redirect(url_for('dashboard_view'))
        
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO cases (case_id, case_name, suspect_name, investigator) VALUES (?, ?, ?, ?)", 
                       (case_id, case_name, suspect_name, investigator))
        conn.commit()
        conn.close()
        flash(f"Successfully mounted investigation Case Profile: {case_id}", "success")
    except sqlite3.IntegrityError:
        flash("Error: Case ID collision detected.", "danger")
    return redirect(url_for('dashboard_view'))

@app.route('/evidence-collector', methods=['POST'])
def evidence_collector():
    case_id = request.form.get('case_id', '').strip()
    file = request.files.get('evidence_file')
    
    if not case_id or not file or file.filename == '':
        flash("Evidence Collector: Data transmission parameters incomplete.", "warning")
        return redirect(url_for('dashboard_view'))
        
    filename = secure_filename(file.filename)
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)
    
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO artifacts (case_id, filename, filesize) VALUES (?, ?, ?)", 
                   (case_id, filename, os.path.getsize(save_path)))
    conn.commit()
    conn.close()
    flash(f"Artifact [{filename}] successfully written to tracking registry.", "success")
    return redirect(url_for('dashboard_view'))

# =========================================================================
# ASYNC MODULE 3: THREAT SIGNATURE DETECTOR (RETURNS JSON)
# =========================================================================
@app.route('/threat-scanner', methods=['POST'])
def threat_scanner():
    file = request.files.get('threat_file')
    if not file or file.filename == '':
        return jsonify({"result": "Error: No file targets loaded into the workspace parameters.", "status": "warning"})
        
    file_bytes = file.read()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    
    if sha256_hash in MALWARE_SIGNATURE_DB:
        threat_identity = MALWARE_SIGNATURE_DB[sha256_hash]
        return jsonify({
            "result": f"⚠️ THREAT MATCH ENCOUNTERED!<br><span class='text-danger'>Hash: {sha256_hash}</span><br>Target Profile: <strong>[{threat_identity}]</strong>", 
            "status": "danger"
        })
    else:
        return jsonify({
            "result": f"✅ COMPLIANCE PASSED:<br>Signature: <span class='text-success'>{sha256_hash}</span><br>Status: File matches clean baseline data.", 
            "status": "success"
        })

# =========================================================================
# ASYNC MODULE 4: LOG TIMELINE PARSER ENGINE (RETURNS JSON)
# =========================================================================
@app.route('/timeline-parser', methods=['POST'])
def timeline_parser():
    raw_log_data = request.form.get('raw_logs', '').strip()
    file = request.files.get('log_file')
    
    if file and file.filename != '':
        raw_log_data = file.read().decode('utf-8', errors='ignore')
        
    if not raw_log_data:
        return jsonify({"results": ["<span class='text-warning'>[Parsing operations dropped. Log target trace stream was empty.]</span>"]})
        
    failed_auth_pattern = re.compile(r'(?P<date>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}).*?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?user\s(?P<user>\w+)')
    parsed_alerts = []
    
    for line in raw_log_data.split('\n'):
        line = line.strip()
        if not line: 
            continue
        if "Authentication Failed" in line or "Failed password" in line or "authentication failure" in line:
            match = failed_auth_pattern.search(line)
            if match:
                parsed_alerts.append(f"<span class='text-danger'>[{match.group('date')}] 🚨 BRUTE FORCE DETECTED: Source host {match.group('ip')} targeted authorization account user '{match.group('user')}'</span>")
            else:
                parsed_alerts.append(f"<span class='text-warning'>⚠️ ANOMALOUS STRIPPED PATTERN RECOVERED: {line[:75]}...</span>")

    if not parsed_alerts:
        parsed_alerts.append("<span class='text-success'>[Analysis complete. Zero log trace structural anomalies recovered from target stream.]</span>")
        
    return jsonify({"results": parsed_alerts})

# =========================================================================
# IMAGE CRYPTOGRAPHIC LAYER OPERATION SYSTEMS
# =========================================================================
@app.route('/image-crypto', methods=['GET', 'POST'])
def image_crypto():
    if 'user' not in session:
        return redirect(url_for('login_node'))
    status, msg_val = None, ""
    if request.method == 'POST':
        action = request.form.get('action')
        pin = request.form.get('pin', '').strip()
        file = request.files.get('image_file')
        message = request.form.get('message', '').strip()
        
        if not file or not pin or not pin.isdigit(): 
            return render_template('image_crypto.html', status="error")
            
        input_bytes = file.read()
        is_unencrypted = input_bytes.startswith(b'\xff\xd8') or input_bytes.startswith(b'\x89PNG') or input_bytes.startswith(b'GIF8')
        
        if action == 'encrypt':
            out_filename = f"crypto_layer_{file.filename}"
            out_path = os.path.join(UPLOAD_FOLDER, out_filename)
            with open(out_path, 'wb') as f: 
                f.write(transform_image_bytes(input_bytes, pin, message))
            return send_file(out_path, as_attachment=True, download_name=out_filename)
            
        elif action == 'decrypt':
            if is_unencrypted: 
                status = "not_encrypted"
            else:
                decrypted = bytearray(input_bytes)
                xor_key = ((sum(int(c) for c in str(pin)) + int(pin)) % 254) + 1
                for i in range(len(decrypted)): 
                    decrypted[i] ^= xor_key
                if b"|VALID_PIN|" in decrypted:
                    status = "success"
                    if b"|SECRET|" in decrypted: 
                        msg_val = decrypted.split(b"|SECRET|", 1)[1].decode('utf-8', errors='ignore').strip()
                else: 
                    status = "wrong_pin"
                    
    return render_template('image_crypto.html', status=status, msg_val=msg_val)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
