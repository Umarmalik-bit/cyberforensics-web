# generate_test_assets.py
import os

print("[+] Generating simulation assets for modules 3 and 4...")

# Create an empty file to test Module 3 Threat Alert
with open("empty_payload.exe", "wb") as f:
    pass
print(" -> Created: empty_payload.exe (0 bytes - Matches Blocklist)")

# Create a clean file to test Module 3 Safe Pass
with open("clean_report.txt", "w") as f:
    f.write("Forensic integrity scan validation text sequence.")
print(" -> Created: clean_report.txt (Clean baseline file)")

# Create a sample raw log file to test Module 4 File Upload option
log_content = """2026-06-14 02:12:01 UTC [SYSTEM_NODE] Inbound connection established from host 192.168.1.105
2026-06-14 02:12:05 UTC [AUTH_KERNEL] Host 192.168.1.105 - Authentication Failed for user root
2026-06-14 02:12:12 UTC [AUTH_KERNEL] Host 192.168.1.105 - Failed password for user admin
2026-06-14 02:12:18 UTC [AUTH_KERNEL] Host 192.168.1.105 - Authentication Failed for user admin
2026-06-14 02:13:45 UTC [AUTH_KERNEL] Host 192.168.1.105 - Failed password for user security_operator
2026-06-14 02:16:01 UTC [AUTH_KERNEL] Host 10.0.0.42 - Unexpected authentication failure sequence on core gateway"""

with open("auth_audit.log", "w") as f:
    f.write(log_content.strip())
print(" -> Created: auth_audit.log (Contains 5 security alerts)")

print("[+] Done. Upload these files to your corresponding dashboard terminals.")