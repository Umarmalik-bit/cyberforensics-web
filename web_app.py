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
    """Initializes the relational database schema for tracking cases and artifacts."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    # Case Management Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            case_name TEXT NOT NULL,
            suspect_name TEXT,
            investigator TEXT NOT NULL
        )
    ''')
    # Artifact tracking table
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

# Initialize database on startup
init_database()


# =========================================================================
# HELPER FUNCTIONS & CRYPTO ENGINES
# =========================================================================

def transform_image_bytes(file_bytes, pin):
    """
    Applies a symmetrical XOR binary stream cipher to the image byte array 
    using a mathematical mask key derived from the user's 4-digit PIN.
    """
    pin_int = int(pin)
    pin_seed = sum(int(char) for char in str(pin)) + pin_int
    byte_array = bytearray(file_bytes)
    xor_key = (pin_seed % 254) + 1  # Ensure key is non-zero (1-255)
    
    for i in range(len(byte_array)):
        byte_array[i] ^= xor_key
        
    return bytes(byte_array)


# =========================================================================
# SYSTEM APPLICATION ROUTES (MODULES 1 - 7)
# =========================================================================

@app.route('/')
@app.route('/dashboard')
def dashboard_view():
    """Renders the main system operations tracking cockpit."""
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

    # Ensure dashboard renders metrics properly without line 105 crash loops
    return render_template('dashboard.html', total_cases=total_cases, total_artifacts=total_artifacts)


@app.route('/case-manager', methods=['GET', 'POST'])
def case_manager():
    """Module 1 & 3: Case Management Lifecycle Registrations Node"""
    if request.method == 'POST':
        case_id = request.form.get('case_id')
        case_name = request.form.get('case_name')
        suspect = request.form.get('suspect_name')
        investigator = request.form.get('investigator_name')
        
        if not case_id or not case_name:
            flash("Validation Fault: Case ID and Title fields are mandatory.", "danger")
            return redirect(url_for('case_manager'))
            
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO cases (case_id, case_name, suspect_name, investigator) VALUES (?, ?, ?, ?)",
                           (case_id, case_name, suspect, investigator))
            conn.commit()
            conn.close()
            flash(f"Success: Forensic Case {case_id} registered into registry index.", "success")
        except sqlite3.IntegrityError:
            flash("Database Conflict: This Case ID already exists within the ledger.", "danger")
            
        return redirect(url_for('case_manager'))

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases")
    all_cases = cursor.fetchall()
    conn.close()
    return render_template('case_manager.html', cases=all_cases)


@app.route('/evidence-collector', methods=['GET', 'POST'])
def evidence_collector():
    """Module 2 & 4: Secure Evidence Artifacts Preservation Node"""
    if request.method == 'POST':
        case_id = request.form.get('case_id')
        file = request.files.get('evidence_file')
        
        if not file or file.filename == '':
            flash("Ingestion Fault: No artifact payload selected.", "danger")
            return redirect(request.url)
            
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
        
        flash(f"Artifact '{filename}' successfully archived and bound to Case ID: {case_id}", "success")
        return redirect(url_for('evidence_collector'))

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM artifacts")
    all_artifacts = cursor.fetchall()
    conn.close()
    return render_template('evidence_collector.html', artifacts=all_artifacts)


@app.route('/threat-scanner', methods=['GET', 'POST'])
def threat_scanner():
    """Module 5: File Malicious Threat Signature Integrity Compliance Scan"""
    scan_results = None
    if request.method == 'POST':
        file = request.files.get('suspect_file')
        if file:
            filename = file.filename
            file_bytes = file.read()
            verdict = "COMPLIANT / SAFE"
            flags = []
            
            # 1. Double Extension Threat Check
            if filename.count('.') > 1:
                verdict = "MALICIOUS / THREAT FLAG"
                flags.append("Deceptive Obfuscation: Double extension detected.")
                
            # 2. Signature Script Injections Parsing
            malicious_signatures = [b"eval(", b"exec(", b"base64_decode", b"<script>", b"DROP TABLE"]
            for signature in malicious_signatures:
                if signature in file_bytes:
                    verdict = "MALICIOUS / THREAT FLAG"
                    flags.append(f"Malicious Signature Match: Found unsafe binary signature {signature.decode('utf-8', errors='ignore')}")
            
            scan_results = {
                'filename': filename,
                'verdict': verdict,
                'flags': flags if flags else ["No anomalies detected during bytecode analysis."]
            }
            
    return render_template('threat_scanner.html', results=scan_results)


@app.route('/timeline-parser', methods=['GET', 'POST'])
def timeline_parser():
    """Module 6: Incident Timeline Log Behavior Pattern Parser Engine"""
    parsed_logs = []
    brute_force_ips = {}
    
    if request.method == 'POST':
        file = request.files.get('log_file')
        if file:
            lines = file.read().decode('utf-8').splitlines()
            for line in lines:
                if "Failed password" in line or "Authentication Failure" in line:
                    parts = line.split()
                    # Mock extraction pattern matching for common log arrays
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
    """Module 7: Secure Image Binary Encryption Matrix Node"""
    if request.method == 'POST':
        action = request.form.get('action')  # Expected: 'encrypt' or 'decrypt'
        pin = request.form.get('pin')
        file = request.files.get('image_file')

        if not file or not file.filename:
            flash("Execution Error: No image file selected for uploading.", "danger")
            return redirect(request.url)
            
        if not pin or len(pin) != 4 or not pin.isdigit():
            flash("Execution Error: PIN must be exactly a 4-digit numeric sequence.", "danger")
            return redirect(request.url)

        input_bytes = file.read()
        if len(input_bytes) == 0:
            flash("Execution Error: The uploaded file contains empty data assets.", "danger")
            return redirect(request.url)

        processed_bytes = transform_image_bytes(input_bytes, pin)

        original_name = file.filename
        if action == 'encrypt':
            out_filename = f"encrypted_{original_name}"
        else:
            if original_name.startswith("encrypted_"):
                out_filename = original_name.replace("encrypted_", "decrypted_", 1)
            else:
                out_filename = f"decrypted_{original_name}"

        out_path = os.path.join(UPLOAD_FOLDER, out_filename)
        with open(out_path, 'wb') as f:
            f.write(processed_bytes)

        return send_file(out_path, as_attachment=True, download_name=out_filename)

    return render_template('image_crypto.html')


# =========================================================================
# APPLICATION ENTRY CONTROL POINT
# =========================================================================

if __name__ == '__main__':
    # Configured for dynamic server environment scaling
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
