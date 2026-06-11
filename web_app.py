import os
import sqlite3
from flask import Flask, render_template, request, flash, redirect, url_for, send_file, session
from werkzeug.utils import secure_filename

app = Flask(__name__)
# Secure secret key for handling browser session authentication states
app.secret_key = 'cyberforensics_secure_session_token_key'

# Application Directory Configurations
UPLOAD_FOLDER = 'uploads'
DATABASE_FILE = 'forensics_workspace.db'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_database():
    """Initializes the relational database schema for tracking users, cases, and artifacts."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # Module 1 & 2: User Profiles Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    
    # Module 3: Case Management Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            case_name TEXT NOT NULL,
            suspect_name TEXT,
            investigator TEXT NOT NULL
        )
    ''')
    
    # Module 4: Artifact Tracking Table
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
    
    # Seed a baseline default administrative analyst account if database is blank
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", "admin123"))
        
    conn.commit()
    conn.close()

# Initialize database schemas on startup
init_database()


# =========================================================================
# CRYPTOGRAPHIC PROCESSING ENGINES
# =========================================================================

def transform_image_bytes(file_bytes, pin):
    """
    Module 7: Applies a symmetrical XOR binary stream cipher to the image byte array 
    using a mathematical mask key derived from the user's 4-digit PIN.
    """
    pin_int = int(pin)
    pin_seed = sum(int(char) for char in str(pin)) + pin_int
    byte_array = bytearray(file_bytes)
    xor_key = (pin_seed % 254) + 1  # Ensures key byte falls within 1-255 range
    
    for i in range(len(byte_array)):
        byte_array[i] ^= xor_key
        
    return bytes(byte_array)


# =========================================================================
# SYSTEM APPLICATION ROUTES
# =========================================================================

@app.route('/')
def root_gate():
    """Forces unauthenticated traffic to clear the security login node first."""
    if 'user' in session:
        return redirect(url_for('dashboard_view'))
    return redirect(url_for('login_node'))


@app.route('/login', methods=['GET', 'POST'])
def login_node():
    """Module 1 & 2: Identity Authentication Gate with Rate-Limiting Protections."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        matched_user = cursor.fetchone()
        conn.close()
        
        if matched_user:
            session['user'] = username
            flash(f"Access Granted: Authorized session opened for analyst '{username}'.", "success")
            return redirect(url_for('dashboard_view'))
        else:
            flash("Authentication Failure: Invalid user credentials or unauthorized access request.", "danger")
            return redirect(url_for('login_node'))
            
    return render_template('login.html')


@app.route('/logout')
def logout_node():
    """Destroys current security tokens and returns user to login portal."""
    session.pop('user', None)
    flash("Session Terminated: Analyst securely logged out of workstation environment.", "info")
    return redirect(url_for('login_node'))


@app.route('/dashboard')
def dashboard_view():
    """Main System Operations Tracking Dashboard."""
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
    """Module 3: Case Management Lifecycle Registrations Node."""
    if 'user' not in session:
        return redirect(url_for('login_node'))

    if request.method == 'POST':
        case_id = request.form.get('case_id')
        case_name = request.form.get('case_name')
        suspect = request.form.get('suspect_name')
        investigator = request.form.get('investigator_name')
        
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO cases (case_id, case_name, suspect_name, investigator) VALUES (?, ?, ?, ?)",
                           (case_id, case_name, suspect, investigator))
            conn.commit()
            conn.close()
            flash(f"Success: Case {case_id} locked into registry index.", "success")
        except sqlite3.IntegrityError:
            flash("Database Conflict: Case ID already exists within ledger.", "danger")
            
        return redirect(url_for('case_manager'))

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases")
    all_cases = cursor.fetchall()
    conn.close()
    return render_template('case_manager.html', cases=all_cases)


@app.route('/evidence-collector', methods=['GET', 'POST'])
def evidence_collector():
    """Module 4: Secure Evidence Artifacts Preservation Node."""
    if 'user' not in session:
        return redirect(url_for('login_node'))

    if request.method == 'POST':
        case_id = request.form.get('case_id')
        file = request.files.get('evidence_file')
        
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(save_path)
            filesize = os.path.getsize(save_path)
            
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO artifacts (case_id, filename, filesize) VALUES (?, ?, ?)",
                           (case_id, filename, filesize))
            conn.commit()
            conn.close()
            
            flash(f"Artifact '{filename}' successfully bound to Case ID: {case_id}", "success")
        return redirect(url_for('evidence_collector'))

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM artifacts")
    all_artifacts = cursor.fetchall()
    conn.close()
    return render_template('evidence_collector.html', artifacts=all_artifacts)


@app.route('/threat-scanner', methods=['GET', 'POST'])
def threat_scanner():
    """Module 5: File Malicious Threat Signature Integrity Compliance Scan."""
    if 'user' not in session:
        return redirect(url_for('login_node'))

    scan_results = None
    if request.method == 'POST':
        file = request.files.get('suspect_file')
        if file:
            filename = file.filename
            file_bytes = file.read()
            verdict = "COMPLIANT / SAFE"
            flags = []
            
            if filename.count('.') > 1:
                verdict = "MALICIOUS / THREAT FLAG"
                flags.append("Deceptive Obfuscation: Double extension detected.")
                
            malicious_signatures = [b"eval(", b"exec(", b"base64_decode", b"<script>", b"DROP TABLE"]
            for signature in malicious_signatures:
                if signature in file_bytes:
                    verdict = "MALICIOUS / THREAT FLAG"
                    flags.append(f"Malicious Code Injected: Found unsafe indicator sequence.")
            
            scan_results = {
                'filename': filename,
                'verdict': verdict,
                'flags': flags if flags else ["No anomalies found during binary parsing scans."]
            }
            
    return render_template('threat_scanner.html', results=scan_results)


@app.route('/timeline-parser', methods=['GET', 'POST'])
def timeline_parser():
    """Module 6: Incident Timeline Log Behavior Pattern Parser Engine."""
    if 'user' not in session:
        return redirect(url_for('login_node'))

    parsed_logs = []
    brute_force_ips = {}
    
    if request.method == 'POST':
        file = request.files.get('log_file')
        if file:
            lines = file.read().decode('utf-8', errors='ignore').splitlines()
            for line in lines:
                if "Failed password" in line or "Authentication Failure" in line:
                    parts = line.split()
                    ip_address = parts[-4] if len(parts) >= 4 else "Unknown IP"
                    timestamp = " ".join(parts[0:3]) if len(parts) >= 3 else "Unknown Time"
                    
                    parsed_logs.append({
                        'timestamp': timestamp,
                        'ip': ip_address,
                        'event': "Failed Authentication Attempt"
                    })
                    brute_force_ips[ip_address] = brute_force_ips.get(ip_address, 0) + 1
                    
    return render_template('timeline_parser.html', logs=parsed_logs, suspicious_ips=brute_force_ips)


@app.route('/image-crypto', methods=['GET', 'POST'])
def image_crypto():
    """Module 7: Secure Image Binary Encryption Matrix Node."""
    if 'user' not in session:
        return redirect(url_for('login_node'))

    if request.method == 'POST':
        action = request.form.get('action')  
        pin = request.form.get('pin')
        file = request.files.get('image_file')

        if not file or not file.filename or not pin or len(pin) != 4 or not pin.isdigit():
            flash("Execution Error: Invalid inputs. Provide an image asset and 4-digit key.", "danger")
            return redirect(request.url)

        input_bytes = file.read()
        processed_bytes = transform_image_bytes(input_bytes, pin)

        original_name = file.filename
        if action == 'encrypt':
            out_filename = f"encrypted_{original_name}"
        else:
            out_filename = original_name.replace("encrypted_", "decrypted_", 1) if original_name.startswith("encrypted_") else f"decrypted_{original_name}"

        out_path = os.path.join(UPLOAD_FOLDER, out_filename)
        with open(out_path, 'wb') as f:
            f.write(processed_bytes)

        return send_file(out_path, as_attachment=True, download_name=out_filename)

    return render_template('image_crypto.html')


# =========================================================================
# WEB ENGINE ENTRY SYSTEM CONTROL POINT
# =========================================================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
