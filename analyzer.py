import cv2
import numpy as np
from PIL import Image
import os
import re

# Shared In-Memory Data Registries (Simulating a Forensic Database)
CASE_DB = []
EVIDENCE_DB = []

# Automated Steganography Configuration Matrix
ID_DATABASE = {
    "1122": {"channel": "Blue", "bit": 0, "name": "Confidential Asset A"},
    "3344": {"channel": "Green", "bit": 2, "name": "Confidential Asset B"},
    "5566": {"channel": "Red", "bit": 1, "name": "Confidential Asset C"}
}

def get_id_parameters(unique_id):
    return ID_DATABASE.get(str(unique_id), None)

def analyze_file_integrity(file_path):
    """Module 3: File Analysis Engine"""
    if not os.path.exists(file_path):
        return {"risk": "Unknown", "details": "File path invalid."}
        
    filename = os.path.basename(file_path).lower()
    file_size = os.path.getsize(file_path)
    extensions = filename.split('.')
    
    risk_level = "Safe"
    reasons = []
    
    if len(extensions) > 2:
        risk_level = "High Risk"
        reasons.append(f"Double extension anomaly detected: '.{extensions[-2]}.{extensions[-1]}'")
        
    if filename.endswith(('.exe', '.bat', '.sh', '.cmd', '.vbs')):
        if risk_level != "High Risk":
            risk_level = "Suspicious"
        reasons.append("Executable script payload inside working directory tree.")
        
    if any(keyword in filename for keyword in ["malware", "hack", "crack", "payload"]):
        risk_level = "High Risk"
        reasons.append("Filename matches high-alert threat intelligence keywords.")
        
    if not reasons:
        reasons.append("No overt structural or behavioral signature match found.")
        
    return {
        "filename": os.path.basename(file_path),
        "size": f"{round(file_size / 1024, 2)} KB",
        "risk": risk_level,
        "details": " | ".join(reasons)
    }

def parse_forensic_logs(log_text):
    """Module 4: Log Analysis Engine"""
    lines = log_text.strip().split('\n')
    failed_attempts = 0
    suspicious_ips = set()
    
    for line in lines:
        if not line:
            continue
        if any(keyword in line.lower() for keyword in ["failed", "unauthorized", "401", "denied"]):
            failed_attempts += 1
            ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            if ip_match:
                suspicious_ips.add(ip_match.group())
                
    verdict = "Stable"
    if failed_attempts >= 5:
        verdict = "Brute Force Attack Detected"
    elif failed_attempts > 0:
        verdict = "Anomalous Signatures Present"
        
    report = f"LOG PARSER ANALYTICS ENGINE VERDICT: {verdict.upper()}\n"
    report += "="*70 + "\n"
    report += f"-> Total Scanned Log Entries    : {len(lines)}\n"
    report += f"-> Failed Authentication Events : {failed_attempts}\n"
    report += f"-> Isolated Attacker Source IPs : {', '.join(suspicious_ips) if suspicious_ips else 'None'}\n"
    return report

def extract_hidden_message(image_path, channel_name, bit_layer):
    """Module 5: Steganography LSB Text Decryptor"""
    img = cv2.imread(image_path)
    if img is None:
        return "[Error: Asset stream reading fault]"
    channel_map = {"Blue": 0, "Green": 1, "Red": 2}
    channel_idx = channel_map.get(channel_name, 0)
    flat_matrix = img[:, :, channel_idx].flatten()
    
    binary_digits = ""
    extracted_chars = ""
    for pixel_val in flat_matrix:
        binary_digits += str((pixel_val >> bit_layer) & 1)
        if len(binary_digits) == 8:
            ascii_val = int(binary_digits, 2)
            current_char = chr(ascii_val) if 32 <= ascii_val <= 126 or ascii_val == 10 else "?"
            extracted_chars += current_char
            binary_digits = ""
            if extracted_chars.endswith("###"):
                return extracted_chars[:-3]
        if len(extracted_chars) > 2000:
            break
    return "[No confidential hidden message sequence located under this ID profile path]"