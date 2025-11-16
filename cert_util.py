"""
This module handles the certificate generation for USB sanitization.
It performs the following:
1. Generates separate SHA-256 hashes of VID, PID, and Serial Number.
2. Combines those hashes to generate a final USB identity hash.
3. Creates a random string, saves it on the USB, and generates its hash.
4. Reads and hashes the binary content of all files on the USB (recursively).
5. Creates a JSON certificate with all these values and an expiry date.
6. Generate the hash of JSON Certificate and then encrypt it using private key.
"""

import os
import json
import string
import secrets
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import subprocess

from usb_info import get_usb_storage_devices
from generate_keys import generate_key_pair

# A centralized, authoritative list of files and folders to ignore during hashing.
IGNORE_LIST = {
    # --- Files ---
    "random_string.txt",
    "usb_certificate.json",
    "public_key.pem",
    "certificate.sig",
    "logs.log",
    # --- Folders ---
    "System Volume Information",
    "$RECYCLE.BIN"
}

def generate_random_string(length=64):
    """
    Generates a secure random alphanumeric string.
    """
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_and_store_cert(drive_letter):
    """
    This is the main function called by usb_watcher.py when a USB is clean.
    It generates all required hashes and saves the certificate on the USB drive.
    """
    base_path = f"{drive_letter}:/"

    # --- Step 1: Get USB Device Info (VID, PID, Serial) ---
    devices = get_usb_storage_devices()
    device = next((d for d in devices if d), None)
    if not device:
        print("No valid USB storage device info found.")
        return

    vid = device["vid"]
    pid = device["pid"]
    serial = device["serial"]

    # --- Step 2: Read All Original Files (Recursively) and Create a Combined Content Hash ---
    content_hasher = hashlib.sha256()
    file_count = 0
    print("Calculating content hash...")
    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_LIST]
        for file in files:
            if file in IGNORE_LIST:
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(4096):
                        content_hasher.update(chunk)
                file_count += 1
            except (IOError, PermissionError):
                print(f"⚠️ Could not read file (skipping): {file_path}")
                continue
    content_hash = content_hasher.hexdigest()
    print("Content hash calculated.")


    # --- Step 3: Create USB ID Hash in memory ---
    vid_hash = hashlib.sha256(vid.encode()).hexdigest()
    pid_hash = hashlib.sha256(pid.encode()).hexdigest()
    serial_hash = hashlib.sha256(serial.encode()).hexdigest()

    combined_hashes = vid_hash + pid_hash + serial_hash
    usb_id_hash = hashlib.sha256(combined_hashes.encode()).hexdigest()

    rand_string = generate_random_string()
    rand_path = os.path.join(base_path, "random_string.txt")

    if os.path.exists(rand_path):
        try:
            subprocess.run(["attrib","-h", rand_path], check=False, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception as e:
            print(f"⚠️ A minor error occurred while making file writable: {e}")

    with open(rand_path, 'w') as f:
        f.write(rand_string)
    rand_hash = hashlib.sha256(rand_string.encode()).hexdigest()

    try:
        subprocess.run(["attrib","+h", rand_path], check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        print(f"✅ Successfully set attributes for '{rand_path}'.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to set attributes. Error: {e.stderr.decode('utf-8').strip()}")
    except FileNotFoundError:
        print("❌ Could not set attributes: 'attrib.exe' was not found in the system PATH.")

    # --- Step 4: Input of Expiry Date ---
    while True:
        try:
            days_valid = int(input("Enter validity duration in days (e.g., 30): "))
            if days_valid <= 0:
                print("❌ Please enter a positive number.")
                continue
            break
        except ValueError:
            print("❌ Invalid input. Please enter a number.")

    expiry_date = (datetime.now() + timedelta(days=days_valid)).strftime("%Y-%m-%d")

    # --- Step 5: Create Final Certificate JSON ---
    cert = {
        "vid": vid,
        "pid": pid,
        "serial_number": serial,
        "usb_id_hash": usb_id_hash,
        "random_string_hash": rand_hash,
        "usb_contents_hash": content_hash,
        "file_count": file_count,
        "expiry_date": expiry_date
    }
    # generate_key_pair()
    cert_path = os.path.join(base_path, "usb_certificate.json")
    with open(cert_path, 'w') as f:
        json.dump(cert, f, indent=4)

    print(f"\n✅ Certificate generated successfully at {cert_path}")

    # --- Step 6: Hash the certificate and sign (encrypt) it with the private key ---
    try:
        # 1. Read the newly created certificate
        with open(cert_path, 'rb') as cert_file:
            certificate_bytes = cert_file.read()

        # MODIFIED: Removed the manual hashing step.
        # The `private_key.sign()` function is designed to take the raw data and the
        # hash algorithm as separate parameters. It performs the hashing internally.
        # By pre-hashing the data ourselves, we were causing a double-hash mismatch.
        # This fix ensures the signing and verification processes are symmetrical.
        # certificate_hash = hashlib.sha256(certificate_bytes).digest() # <-- THIS LINE WAS REMOVED

        # 2. Load the private key from the host machine
        with open("C:/Windows/private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        # 3. Sign the raw certificate data using the private key
        signature = private_key.sign(
            certificate_bytes, # <-- MODIFIED: Pass the raw bytes, not the pre-computed hash.
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.MGF1.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # 4. Save the encrypted signature to a new file on the USB
        sig_path = os.path.join(base_path, "certificate.sig")
        with open(sig_path, "wb") as f:
            f.write(signature)
        print(f"✅ Certificate signature generated successfully at {sig_path}")

    except FileNotFoundError:
        print("❌ ERROR: 'private_key.pem' not found in C:/Windows/. Please run generate_key.py on the admin machine.")
    except Exception as e:
        print(f"❌ An error occurred during certificate signing: {e}")
