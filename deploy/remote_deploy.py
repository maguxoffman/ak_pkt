#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import pexpect

HOST = "172.20.20.98"
USER = "root"
PASS = "magdata100$"
REMOTE_DIR = "/var/ai_pkt"
LOCAL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAR_FILE = "/tmp/ai_pkt_deploy.tar.gz"

def run_ssh_command(cmd, timeout=300):
    print(f"\n👉 [SSH Exec] {cmd}")
    ssh_cmd = f'ssh -o StrictHostKeyChecking=no {USER}@{HOST} "{cmd}"'
    child = pexpect.spawn(ssh_cmd, timeout=timeout)
    
    while True:
        idx = child.expect(['[pP]assword:', pexpect.EOF, pexpect.TIMEOUT])
        if idx == 0:
            child.sendline(PASS)
        elif idx == 1:
            output = child.before.decode('utf-8', errors='ignore')
            print(output)
            return child.exitstatus
        elif idx == 2:
            print("❌ SSH Command Timed Out")
            output = child.before.decode('utf-8', errors='ignore')
            print(output)
            return -1

def run_scp_upload(local_path, remote_path, timeout=300):
    print(f"\n📤 [SCP Upload] {local_path} -> {USER}@{HOST}:{remote_path}")
    scp_cmd = f'scp -o StrictHostKeyChecking=no {local_path} {USER}@{HOST}:{remote_path}'
    child = pexpect.spawn(scp_cmd, timeout=timeout)
    
    while True:
        idx = child.expect(['[pP]assword:', pexpect.EOF, pexpect.TIMEOUT])
        if idx == 0:
            child.sendline(PASS)
        elif idx == 1:
            output = child.before.decode('utf-8', errors='ignore')
            print(output)
            return child.exitstatus
        elif idx == 2:
            print("❌ SCP Upload Timed Out")
            return -1

def main():
    print(f"====================================================================")
    print(f"🚀 Automated Remote Deployment to Rocky Linux 9.4 ({HOST})")
    print(f"====================================================================")

    # Step 1: Create Local Tar Archive
    print("\n📦 Step 1: Creating Deployment Tar Archive...")
    if os.path.exists(TAR_FILE):
        os.remove(TAR_FILE)
        
    tar_cmd = [
        "tar", "-czf", TAR_FILE,
        "--exclude=venv", "--exclude=__pycache__", "--exclude=.git",
        "--exclude=*.pyc", "--exclude=.DS_Store",
        "-C", LOCAL_ROOT, "."
    ]
    subprocess.check_call(tar_cmd)
    print(f"✅ Archive created: {TAR_FILE} ({os.path.getsize(TAR_FILE) / 1024 / 1024:.2f} MB)")

    # Step 2: Upload Archive via SCP
    print("\n📤 Step 2: Uploading Tar Archive to Target Server...")
    run_scp_upload(TAR_FILE, "/tmp/ai_pkt_deploy.tar.gz")

    # Step 3: Create Remote Directory and Extract Code
    print("\n📂 Step 3: Extracting Files to /var/ai_pkt...")
    extract_script = f"mkdir -p {REMOTE_DIR} && tar -xzf /tmp/ai_pkt_deploy.tar.gz -C {REMOTE_DIR} && rm -f /tmp/ai_pkt_deploy.tar.gz"
    run_ssh_command(extract_script)

    # Step 4: Make Scripts Executable & Run Installation
    print("\n⚡ Step 4: Executing install_rocky94.sh on Remote Server...")
    install_script = f"cd {REMOTE_DIR}/deploy && chmod +x *.sh && ./install_rocky94.sh"
    run_ssh_command(install_script, timeout=600)

    # Step 5: Health Check & Verification
    print("\n🔍 Step 5: Running Remote Service Verification...")
    verify_script = f"cd {REMOTE_DIR}/deploy && ./status.sh"
    run_ssh_command(verify_script)

    print(f"\n====================================================================")
    print(f"✅ Remote Deployment Completed Successfully on {HOST}!")
    print(f"====================================================================")
    print(f"🌐 Remote Web Dashboard : http://{HOST}:3000")
    print(f"⚡ Remote Backend API  : http://{HOST}:8000")
    print(f"📂 Remote Directory    : {REMOTE_DIR}")
    print(f"====================================================================")

if __name__ == "__main__":
    main()
