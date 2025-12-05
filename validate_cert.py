# validate_cert.py
#
# This module contains the USBCertificateValidator class. Its ONLY responsibility
# is to perform a series of checks on a given file path (the sandboxed drive)
# and return True if the certificate is valid, or False otherwise.
# It performs NO actions like ejecting or starting monitoring.

import os
import json
import hashlib
import time
import subprocess
from datetime import datetime

# --- Core Dependencies & Project Modules ---
try:
    from usb_info import get_usb_storage_devices
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
except ImportError as e:
    # This indicates a setup problem. The worker script that calls this will handle the error.
    raise ImportError(f"A required library for validation is missing: {e}")

# This list is used by the hashing function to ignore certificate-related files.
IGNORE_LIST = {
    "random_string.txt", "usb_certificate.json", "public_key.pem",
    "certificate.sig", "logs.log", "System Volume Information", "$RECYCLE.BIN"
}

class USBCertificateValidator:
    def __init__(self, original_drive_letter):
        """
        Initializes the validator.
        Args:
            original_drive_letter (str): The original letter (e.g., 'E') for context.
        """
        # The original drive letter is stored for context and hardware checks.
        self.drive_letter = original_drive_letter
        # This base_path WILL BE OVERRIDDEN by the worker script to point to the sandbox.
        self.base_path = f"{original_drive_letter}:\\"

    def validate_certificate(self) -> bool:
        """
        Main validation logic. Operates on self.base_path, which must point to the sandbox.
        Returns True if all checks pass, False otherwise.
        """
        print(f"\n--- Validating USB Drive {self.drive_letter} ---")
        cert_path = os.path.join(self.base_path, "usb_certificate.json")
        rand_path = os.path.join(self.base_path, "random_string.txt")
        sig_path = os.path.join(self.base_path, "certificate.sig")
        
        # Look for public key on the HOST SYSTEM, not the USB.
        # 1. Check C:\Windows\public_key.pem (Standard location)
        pub_key_path = os.path.join("C:\\", "Windows", "public_key.pem")
        if not os.path.exists(pub_key_path):
            # 2. Check current script directory (Fallback)
            pub_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public_key.pem")

        if not os.path.exists(pub_key_path):
             print(f"[FAIL] Public Key not found on Client System.")
             print("Please ensure 'public_key.pem' is in C:\\Windows\\ or the script directory.")
             # Fallback to checking the USB drive itself, just in case legacy setup
             pub_key_path_usb = os.path.join(self.base_path, "public_key.pem")
             if os.path.exists(pub_key_path_usb):
                 print(f"Warning: Using public key from USB drive (Less Secure).")
                 pub_key_path = pub_key_path_usb
             else:
                 return False

        # 1. Check for required files on USB
        missing_files = []
        # Removed public_key.pem from this list as it is now checked locally
        for p_name in ["usb_certificate.json", "random_string.txt", "certificate.sig"]:
             full_p = os.path.join(self.base_path, p_name)
             if not os.path.exists(full_p):
                 missing_files.append(p_name)
        
        if missing_files:
            print(f"[FAIL] Missing files on USB: {missing_files}")
            print(f"Debug: Looking in {self.base_path}")
            try:
                print(f"Debug: Directory contents: {os.listdir(self.base_path)}")
            except Exception as e:
                print(f"Debug: Could not list directory: {e}")
            return False

        # 2. Load the certificate
        try:
            with open(cert_path, 'r') as f:
                cert = json.load(f)
        except Exception:
            print("[FAIL] Certificate file 'usb_certificate.json' is corrupted.")
            return False

        # 3. Perform all validation checks in order. If any fail, the function returns False.
        if not self._verify_expiry(cert): return False
        if not self._verify_usb_identity(cert): return False
        if not self._verify_random_string(cert, rand_path): return False
        if not self._verify_content_hashes(cert): return False
        if not self._verify_signature(cert, cert_path, sig_path, pub_key_path): return False

        # If all checks passed:
        print(f"--- [SUCCESS] Drive {self.drive_letter}: is validated and trusted. ---")
        return True

    def _verify_expiry(self, cert):
        print("[Check 1/5] Verifying expiry date...", end=" ")
        try:
            if datetime.now() >= datetime.strptime(cert['expiry_date'], "%Y-%m-%d"):
                print("FAILED (Expired)")
                return False
        except (ValueError, KeyError):
            print("FAILED (Invalid Date Format)")
            return False
        print("OK")
        return True

    def _verify_usb_identity(self, cert):
        print("[Check 2/5] Verifying USB hardware identity...", end=" ")
        devices = get_usb_storage_devices()
        device = next((d for d in devices if d['serial'] == cert.get('serial_number')), None)
        if not device:
            print("FAILED (Device with specified serial not found)")
            return False

        vid_hash = hashlib.sha256(device['vid'].encode()).hexdigest()
        pid_hash = hashlib.sha256(device['pid'].encode()).hexdigest()
        serial_hash = hashlib.sha256(device['serial'].encode()).hexdigest()
        current_id_hash = hashlib.sha256((vid_hash + pid_hash + serial_hash).encode()).hexdigest()
        if current_id_hash != cert.get('usb_id_hash'):
            print("FAILED (Hardware mismatch)")
            return False
        print("OK")
        return True

    def _verify_random_string(self, cert, rand_path):
        print("[Check 3/5] Verifying random string hash...", end=" ")
        try:
            subprocess.run(["attrib", "-s", "-r", "-h", "-i", rand_path], check=False, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            with open(rand_path, 'r') as f:
                current_hash = hashlib.sha256(f.read().encode()).hexdigest()
            if current_hash != cert.get('random_string_hash'):
                print("FAILED (File tampered)")
                return False
        except IOError:
            print("FAILED (Cannot read file)")
            return False
        finally:
            subprocess.run(["attrib", "+s", "+h", "+r", "+i", rand_path], check=False, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        print("OK")
        return True

    def _verify_content_hashes(self, cert):
        print("[Check 4/5] Verifying USB content hash...", end=" ")
        content_hasher = hashlib.sha256()
        file_count = 0
        try:
            for root, dirs, files in os.walk(self.base_path):
                dirs[:] = [d for d in dirs if d not in IGNORE_LIST]
                for file in files:
                    if file in IGNORE_LIST: continue
                    with open(os.path.join(root, file), 'rb') as f:
                        read_size = 0
                        MAX_HASH_SIZE = 10 * 1024 * 1024
                        while chunk := f.read(4096):
                            content_hasher.update(chunk)
                            read_size += len(chunk)
                            if read_size >= MAX_HASH_SIZE:
                                break
                    file_count += 1
        except (IOError, PermissionError):
            print("FAILED (Error reading file content)")
            return False

        if content_hasher.hexdigest() != cert.get('usb_contents_hash'):
             print("FAILED (Content modified)")
             return False
        if file_count != cert.get('file_count'):
            print("FAILED (File count changed)")
            return False
        print("OK")
        return True

    def _verify_signature(self, cert, cert_path, sig_path, pub_key_path):
        print("[Check 5/5] Verifying digital signature...", end=" ")
        try:
            with open(pub_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())
            with open(cert_path, "rb") as cert_file:
                certificate_data = cert_file.read()
            with open(sig_path, "rb") as sig_file:
                signature = sig_file.read()
            public_key.verify(
                signature,
                certificate_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        except Exception:
            print("FAILED (Invalid Signature)")
            return False
        print("OK")
        return True
