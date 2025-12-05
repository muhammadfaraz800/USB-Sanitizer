# helper.py
#
# This script handles the entire sandboxing and validation for a SINGLE drive.
# It is designed to be called by a watcher script as a separate process.
#
# Usage: python helper.py E:

import os
import json
import hashlib
import time
import subprocess
import ctypes
import sys
from datetime import datetime

# --- Imports from existing project files ---
try:
    import win32file
    from usb_ejector import eject_drive
    from usb_logger import log_usb_activity
    from usb_info import get_usb_storage_devices
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
except ImportError as e:
    # If this script fails, it's a critical error.
    print(f"FATAL: Missing required library or project file: {e}")
    sys.exit(1)


# --- Sandboxing Functions ---

def get_volume_guid(drive_letter: str) -> str:
    """
    Waits patiently for a drive to be ready and returns its GUID.
    """
    print(f"[{drive_letter}] Waiting for drive to initialize...")
    for _ in range(10):  # Try for 5 seconds
        letter_with_slash = drive_letter.rstrip('\\') + '\\'
        if os.path.exists(letter_with_slash):
            try:
                guid = win32file.GetVolumeNameForVolumeMountPoint(letter_with_slash)
                print(f"[{drive_letter}] Drive ready. GUID found.")
                return guid
            except win32file.error:
                pass  # Ignore error and retry
        time.sleep(0.5)
    print(f"[{drive_letter}] CRITICAL: Could not get Volume GUID after 5 seconds.")
    return None


def mount_to_folder(volume_guid: str, mount_folder: str) -> bool:
    try:
        os.makedirs(mount_folder, exist_ok=True)
        mount_path_with_slash = mount_folder.rstrip('\\') + '\\'
        win32file.SetVolumeMountPoint(mount_path_with_slash, volume_guid)
        subprocess.run(
            ["attrib", "+s", "+h", mount_folder],
            check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        return True
    except Exception as e:
        print(f"Error mounting volume to {mount_folder}: {e}")
        return False


def unmount_from_folder(mount_folder: str) -> bool:
    try:
        mount_path_with_slash = mount_folder.rstrip('\\') + '\\'
        win32file.DeleteVolumeMountPoint(mount_path_with_slash)
        try:
            os.rmdir(mount_folder)
        except OSError:
            pass
        return True
    except Exception as e:
        print(f"Error unmounting from {mount_folder}: {e}")
        return False


def change_drive_letter(volume_guid: str, drive_letter: str) -> bool:
    try:
        letter_with_slash = drive_letter.rstrip('\\') + '\\'
        win32file.SetVolumeMountPoint(letter_with_slash, volume_guid)
        return True
    except Exception as e:
        print(f"Error setting drive letter {drive_letter}: {e}")
        return False


def remove_drive_letter(drive_letter: str) -> bool:
    try:
        letter_with_slash = drive_letter.rstrip('\\') + '\\'
        win32file.DeleteVolumeMountPoint(letter_with_slash)
        return True
    except Exception as e:
        print(f"Error removing drive letter {drive_letter}: {e}")
        return False


# --- Certificate Validation Logic ---

def perform_sandboxed_validation(sandboxed_path: str, original_drive_letter: str) -> bool:
    """
    This is the core validation function, operating on the hidden sandbox folder.
    Returns True if the certificate is valid, False otherwise.
    """
    print(f"--- Validating content in sandbox: {sandboxed_path} ---")

    # Define paths inside the sandbox
    cert_path = os.path.join(sandboxed_path, "usb_certificate.json")
    rand_path = os.path.join(sandboxed_path, "random_string.txt")
    sig_path = os.path.join(sandboxed_path, "certificate.sig")
    pub_key_path = os.path.join(sandboxed_path, "public_key.pem")

    # Define the ignore list for hashing
    ignore_list = {
        "random_string.txt", "usb_certificate.json", "public_key.pem",
        "certificate.sig", "logs.log", "System Volume Information", "$RECYCLE.BIN"
    }

    # 1. Check for required files
    if not all(os.path.exists(p) for p in [cert_path, rand_path, sig_path, pub_key_path]):
        print("[FAIL] Missing one or more certificate files.")
        return False

    # 2. Load and verify certificate JSON
    try:
        with open(cert_path, 'r') as f:
            cert = json.load(f)
    except Exception as e:
        print(f"[FAIL] Certificate file is corrupted: {e}")
        return False

    # 3. All subsequent checks...
    # (The logic from USBCertificateValidator is condensed here for a linear script)

    # Check Expiry
    try:
        if datetime.now() >= datetime.strptime(cert['expiry_date'], "%Y-%m-%d"):
            print(f"[FAIL] Certificate expired on {cert['expiry_date']}")
            return False
    except (ValueError, KeyError):
        print("[FAIL] Invalid or missing expiry date.")
        return False

    # Check Hardware Identity
    devices = get_usb_storage_devices()
    device = next((d for d in devices if d['serial'] == cert.get('serial_number')), None)
    if not device:
        print("[FAIL] Could not find a USB with the serial number in the certificate.")
        return False
    vid_hash = hashlib.sha256(device['vid'].encode()).hexdigest()
    pid_hash = hashlib.sha256(device['pid'].encode()).hexdigest()
    serial_hash = hashlib.sha256(device['serial'].encode()).hexdigest()
    current_id_hash = hashlib.sha256((vid_hash + pid_hash + serial_hash).encode()).hexdigest()
    if current_id_hash != cert.get('usb_id_hash'):
        print("[FAIL] USB identity hash mismatch.")
        return False

    # Check Content Hash
    content_hasher = hashlib.sha256()
    file_count = 0
    for root, dirs, files in os.walk(sandboxed_path):
        dirs[:] = [d for d in dirs if d not in ignore_list]
        for file in files:
            if file in ignore_list: continue
            try:
                with open(os.path.join(root, file), 'rb') as f:
                    while chunk := f.read(4096):
                        content_hasher.update(chunk)
                file_count += 1
            except (IOError, PermissionError):
                continue
    if content_hasher.hexdigest() != cert.get('usb_contents_hash') or file_count != cert.get('file_count'):
        print("[FAIL] Content hash or file count mismatch.")
        return False

    # Check Signature
    try:
        with open(pub_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        with open(cert_path, "rb") as cert_file:
            certificate_data = cert_file.read()
        with open(sig_path, "rb") as sig_file:
            signature = sig_file.read()
        public_key.verify(signature, certificate_data,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
    except Exception as e:
        print(f"[FAIL] Signature verification failed: {e}.")
        return False

    print("--- [SUCCESS] All certificate checks passed. ---")
    log_usb_activity(f"{original_drive_letter}:\\", "[VALIDATION SUCCESS]", "All checks passed.")
    return True


# --- Main Execution Block ---

def main():
    if len(sys.argv) < 2:
        print("Usage: python helper.py <drive_letter>")
        sys.exit(1)

    usb_drive = sys.argv[1].upper().rstrip(':\\')
    temp_mount = f"C:\\usb_temp_mount\\{usb_drive}"

    guid = get_volume_guid(usb_drive)
    if not guid:
        sys.exit(1)  # Exit if drive is not ready

    if not remove_drive_letter(usb_drive):
        sys.exit(1)

    if not mount_to_folder(guid, temp_mount):
        # Attempt to restore the letter if mounting fails
        change_drive_letter(guid, usb_drive)
        sys.exit(1)

    # Perform the validation in the sandbox
    is_valid = perform_sandboxed_validation(temp_mount, usb_drive)

    # Always clean up and restore the drive letter
    unmount_from_folder(temp_mount)
    if not change_drive_letter(guid, usb_drive):
        print(f"[{usb_drive}] CRITICAL: Could not restore drive letter. Manual intervention may be required.")

    # Take action based on the validation result
    time.sleep(1)  # Give OS a moment to re-register the drive letter
    if is_valid:
        print(f"[{usb_drive}] Validation successful. USB is now accessible.")
    else:
        print(f"[{usb_drive}] Validation FAILED. Ejecting drive.")
        log_usb_activity(f"{usb_drive}:\\", "[VALIDATION FAILED]", "Ejecting invalid drive.")
        eject_drive(usb_drive)


if __name__ == "__main__":
    main()
