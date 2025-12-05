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

# It's better to import these at the top level
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

def generate_and_store_cert(drive_letter, days_valid, vid=None, pid=None, serial=None):
    """
    This is the main function called by the GUI. It generates all required hashes
    and saves the certificate on the USB drive.

    Args:
        drive_letter (str): The letter of the USB drive (e.g., 'E').
        days_valid (int): The number of days the certificate should be valid for.
        vid (str, optional): VID of the device.
        pid (str, optional): PID of the device.
        serial (str, optional): Serial number.
    """
    base_path = f"{drive_letter}:/"

    # --- Step 1: Get USB Device Info (VID, PID, Serial) ---
    if not (vid and pid and serial):
        print("Querying USB device info...")
        devices = get_usb_storage_devices()
        # Find the specific device that matches the drive letter's serial, if possible.
        # This is complex, so for now we take the first available storage device.
        device = next((d for d in devices), None)
        if not device:
            print("No valid USB storage device info found.")
            # Optionally, raise an exception to be caught by the GUI
            raise ConnectionError("Could not retrieve USB device hardware details.")
        
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
                # OPTIMIZATION: Only hash the first 10MB of files to prevent hanging on large media
                MAX_HASH_SIZE = 10 * 1024 * 1024
                read_size = 0
                with open(file_path, 'rb') as f:
                    while chunk := f.read(4096):
                        content_hasher.update(chunk)
                        read_size += len(chunk)
                        if read_size >= MAX_HASH_SIZE:
                            break
                            
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
            subprocess.run(["attrib", "-s","-h","-r","-i", rand_path], check=False, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
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

    # --- Step 4: Use the expiry date passed from the GUI ---
    if not isinstance(days_valid, int) or days_valid <= 0:
        raise ValueError("Certificate validity must be a positive number of days.")

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

    cert_path = os.path.join(base_path, "usb_certificate.json")
    with open(cert_path, 'w') as f:
        json.dump(cert, f, indent=4)

    print(f"\n✅ Certificate generated successfully at {cert_path}")

    # --- Step 6: Hash the certificate and sign (encrypt) it with the private key ---
    try:
        with open(cert_path, 'rb') as cert_file:
            certificate_bytes = cert_file.read()

        private_key_pem_path = "C:/Windows/private_key.pem"
        if not os.path.exists(private_key_pem_path):
            raise FileNotFoundError("Private key not found. Please run generate_keys.py first as Admin.")

        with open(private_key_pem_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        signature = private_key.sign(
            certificate_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        sig_path = os.path.join(base_path, "certificate.sig")
        with open(sig_path, "wb") as f:
            f.write(signature)
        print(f"✅ Certificate signature generated successfully at {sig_path}")

    except FileNotFoundError as e:
        print(f"❌ ERROR: {e}")
        raise # Re-raise the exception so the GUI can catch it
    except Exception as e:
        print(f"❌ An error occurred during certificate signing: {e}")
        raise # Re-raise the exception
