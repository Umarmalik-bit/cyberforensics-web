from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import os
import re
from datetime import datetime
import analyzer

app = Flask(__name__)
app.secret_key = "SSUET_METRIC_SECRET_KEY_POLYMORPHIC" # Required to maintain secure sessions

# Core User Security Registry Engine Matrix
# Simulating a multi-tenant environment with automated tracking state variables
USERS_DB = {}

def evaluate_password_strength(password):
    """Calculates password structural strength complexity."""
    if len(password) < 6:
        return "Weak"
    # Strong if it contains numbers, uppercase letters, and special symbols
    if (re.search(r"\d", password) and 
        re.search(r"[A-Z]", password) and 
        re.search(r"[ !@#$%^&*(),.?\":{}|<>_]", password)):
        return "Strong"
    return "Normal"

@app.route('/')
def root():
    if 'username' in session:
        return redirect(url_for('dashboard_view'))
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/api/auth/register', methods=['POST'])
def handle_register():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        return jsonify({"success": False, "error": "Fields cannot be blank."})
        
    if username in USERS_DB:
        return jsonify({"success": False, "error": f"Username '{username}' is already allocated."})
        
    strength = evaluate_password_strength(password)
    
    # Initialize separate, distinct virtual vault memory pools for this specific user profile
    USERS_DB[username] = {
        "password": password,
        "failed_attempts": 0,
        "CASE_DB": [],
        "EVIDENCE_DB": []
    }
    
    return jsonify({"success": True, "strength": strength})

@app.route('/api/auth/login', methods=['POST'])
def handle_login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if username not in USERS_DB:
        return jsonify({"success": False, "error": "Identity signature not registered."})
        
    user_profile = USERS_DB[username]
    
    if user_profile["password"] == password:
        # Reset counters on clean verification authentication instance
        user_profile["failed_attempts"] = 0
        session['username'] = username
        return jsonify({"success": True, "redirect": url_for('dashboard_view')})
    else:
        user_profile["failed_attempts"] += 1
        remaining = 3 - user_profile["failed_attempts"]
        
        # --- TRIGGER ANTI-FORENSIC SELF DESTRUCT WIPE PROTOCOL ---
        if user_profile["failed_attempts"] >= 3:
            del USERS_DB[username] # Complete extraction purge from address registries mapping matrices
            if 'username' in session and session['username'] == username:
                session.pop('username', None)
            return jsonify({
                "success": False, 
                "error": "CRITICAL THREAT ALERT: 3 Failed attempts logged consecutively. Account tracking signature has been permanently terminated and vault arrays completely purged!"
            })
            
        return jsonify({
            "success": False, 
            "error": f"Invalid passphrase token value signature. Consecutive Threshold Breach Alert: Account self-destruct sequence triggers in {remaining} more attempt(s)."
        })

@app.route('/logout')
def handle_logout():
    session.pop('username', None)
    return redirect(url_for('login_page'))

# ==================================================================================
# MULTI-TENANT WORKSPACE ROUTING OVERLAYS (Maps Global logic arrays to Active Session Users)
# ==================================================================================
@app.route('/dashboard')
def dashboard_view():
    if 'username' not in session: return redirect(url_for('login_page'))
    u = session['username']
    return render_template('dashboard.html', 
                           case_count=len(USERS_DB[u]["CASE_DB"]), 
                           evidence_count=len(USERS_DB[u]["EVIDENCE_DB"]))

@app.route('/api/case/add', methods=['POST'])
def add_case():
    if 'username' not in session: return jsonify({"success": False})
    u = session['username']
    case_id = request.form.get('case_id')
    description = request.form.get('description')
    if case_id and description:
        entry = f"ID: {case_id} | Type: {description}"
        USERS_DB[u]["CASE_DB"].append(entry)
        return jsonify({"success": True, "entry": entry, "count": len(USERS_DB[u]["CASE_DB"])})
    return jsonify({"success": False})

@app.route('/api/evidence/upload', methods=['POST'])
def upload_evidence():
    if 'username' not in session: return jsonify({"success": False})
    u = session['username']
    if 'file' not in request.files: return jsonify({"success": False})
    file = request.files['file']
    
    tag = "SUSPICIOUS" if file.filename.endswith(('.exe', '.bat', '.sh', '.png')) else "SAFE"
    entry = f"File: {file.filename} -> TAG: [{tag}]"
    USERS_DB[u]["EVIDENCE_DB"].append(entry)
    return jsonify({"success": True, "entry": entry, "count": len(USERS_DB[u]["EVIDENCE_DB"])})

@app.route('/api/analyze/file', methods=['POST'])
def analyze_file():
    if 'file' not in request.files: return jsonify({"error": "No file"})
    file = request.files['file']
    file_path = os.path.join(os.getcwd(), file.filename)
    file.save(file_path)
    result = analyzer.analyze_file_integrity(file_path)
    try: os.remove(file_path) # Clean staging buffer space directly right after mapping parse routines
    except: pass
    return jsonify(result)

@app.route('/api/analyze/logs', methods=['POST'])
def analyze_logs():
    return jsonify({"report": analyzer.parse_forensic_logs(request.form.get('logs', ''))})

@app.route('/api/decrypt/stego', methods=['POST'])
def decrypt_stego():
    user_id = request.form.get('user_id')
    file = request.files['file']
    file_path = os.path.join(os.getcwd(), file.filename)
    file.save(file_path)
    
    meta = analyzer.get_id_parameters(user_id)
    if not meta: return jsonify({"error": f"ACCESS DENIED: Token key invalid."})
    msg = analyzer.extract_hidden_message(file_path, meta['channel'], meta['bit'])
    try: os.remove(file_path)
    except: pass
    
    return jsonify({"report": f"AUTHENTICATION CONFIRMED: Profile Clearance Verified -> {meta['name']}\n======================================================================\n-> Payload String: \" {msg} \""})

@app.route('/api/report/compile', methods=['GET'])
def compile_report():
    if 'username' not in session: return jsonify({"report": ""})
    u = session['username']
    rep = f"CYBERFORENSICS WORKSTATION LIVE DATA CAPTURE REPORT MAPPING\n"
    rep += "="*75 + "\n"
    rep += f"Active Operational Profiler Entity Target : User account session [{u.upper()}]\n"
    rep += f"Compiled Timeline Sequence Instance : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    rep += "="*75 + "\n\n"
    rep += "[SECTION I: CASES REGISTRY DIRECTORY]\n"
    for c in USERS_DB[u]["CASE_DB"]: rep += f" - {c}\n"
    rep += "\n[SECTION II: SECURE VAULT CONTAINER MANIFEST]\n"
    for e in USERS_DB[u]["EVIDENCE_DB"]: rep += f" - {e}\n"
    return jsonify({"report": rep})

if __name__ == '__main__':
    app.run(debug=True, port=5000)