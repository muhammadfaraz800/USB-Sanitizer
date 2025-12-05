import os
import json
import hashlib
import time
import subprocess
import ctypes
import sys
from datetime import datetime
import threading
import psutil

# Import required modules
from usb_ejector import eject_drive
from usb_logger import log_usb_activity
from usb_info import get_usb_storage_devices
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from usb_file_monitor import monitor_usb

# MODIFIED: A centralized, authoritative list of files and folders to ignore during hashing.
# This ensures both creation and validation use the exact same rules.
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


class USBCertificateValidator:
    def __init__(self, drive_letter):
        self.drive_letter = drive_letter
        self.base_path = f"{drive_letter}:\\"
        self.observer = None

    def start_file_monitoring(self):
        """Starts the file monitor and returns the observer object."""
        print(f"[{self.drive_letter}:] Starting file activity monitoring...")
        self.observer = monitor_usb(self.drive_letter)
        log_usb_activity(
            self.base_path,
            "[MONITORING STARTED]",
            pasted="File monitoring initialized."
        )

    def stop_file_monitoring(self):
        """Stops the file monitor if it is running."""
        if self.observer and self.observer.is_alive():
            print(f"[{self.drive_letter}:] Stopping file activity monitoring...")
            self.observer.stop()
            self.observer.join()
            log_usb_activity(
                self.base_path,
                "[MONITORING STOPPED]",
                pasted="File monitoring terminated."
            )

    def validate_certificate(self):
        print(f"\n--- Validating USB Drive {self.drive_letter}: ---")
        cert_path = os.path.join(self.base_path, "usb_certificate.json")
        rand_path = os.path.join(self.base_path, "random_string.txt")
        sig_path = os.path.join(self.base_path, "certificate.sig")
        pub_key_path = os.path.join(self.base_path, "public_key.pem")

        print("[1/6] Checking for required files...", end=" ")
        if not all(os.path.exists(p) for p in [cert_path, rand_path, sig_path, pub_key_path]):
            print("Certificate verification FAILED")
            self._handle_validation_failure("Missing one or more certificate files.")
            return False
        print("OK")

        try:
            with open(cert_path, 'r') as f:
                cert = json.load(f)
        except Exception as e:
            self._handle_validation_failure(f"Certificate file is corrupted: {e}")
            return False

        print("[2/6] Verifying expiry date...", end=" ")
        try:
            expiry_date = datetime.strptime(cert['expiry_date'], "%Y-%m-%d")
            if datetime.now() >= expiry_date:
                print("FAILED")
                self._handle_validation_failure(f"Certificate expired on {cert['expiry_date']}")
                return False
        except (ValueError, KeyError) as e:
            print("FAILED")
            self._handle_validation_failure(f"Invalid or missing expiry date: {e}")
            return False
        print(f"OK (Expires: {cert['expiry_date']})")

        print("[3/6] Verifying USB hardware identity...", end=" ")
        if not self._verify_usb_identity(cert):
            print("FAILED")
            return False
        print("OK")

        print("[4/6] Verifying random string hash...", end=" ")
        if not self._verify_random_string(cert, rand_path):
            print("FAILED")
            return False
        print("OK")

        print("[5/6] Verifying USB content hash...", end=" ")
        if not self._verify_content_hashes(cert):
            print("FAILED")
            return False
        print("OK")

        print("[6/6] Verifying digital signature...", end=" ")
        if not self._verify_signature(cert, cert_path, sig_path, pub_key_path):
            print("FAILED")
            return False
        print("OK")

        print(f"--- [SUCCESS] Drive {self.drive_letter}: is validated and trusted. ---")
        log_usb_activity(self.base_path, "[VALIDATION SUCCESS]", pasted="All checks passed.")
        return True

    def _verify_usb_identity(self, cert):
        devices = get_usb_storage_devices()
        device = next((d for d in devices if d['serial'] == cert.get('serial_number')), None)
        if not device:
            self._handle_validation_failure("Could not find a USB with the serial number in the certificate.")
            return False

        vid_hash = hashlib.sha256(device['vid'].encode()).hexdigest()
        pid_hash = hashlib.sha256(device['pid'].encode()).hexdigest()
        serial_hash = hashlib.sha256(device['serial'].encode()).hexdigest()
        current_hash = hashlib.sha256((vid_hash + pid_hash + serial_hash).encode()).hexdigest()

        if current_hash != cert.get('usb_id_hash'):
            self._handle_validation_failure("USB identity hash mismatch.")
            return False
        return True

    def _verify_random_string(self, cert, rand_path):
        try:
            subprocess.run(["attrib", "-s", "-r", "-h", "-i", rand_path], check=False, capture_output=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            with open(rand_path, 'r') as f:
                current_hash = hashlib.sha256(f.read().encode()).hexdigest()
            if current_hash != cert.get('random_string_hash'):
                self._handle_validation_failure("Random string hash mismatch.")
                return False
            return True
        except IOError as e:
            self._handle_validation_failure(f"Cannot read random string file: {e}")
            return False
        finally:
            subprocess.run(["attrib", "+s", "+h", "+r", "+i", rand_path], check=False, capture_output=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)

    def _verify_content_hashes(self, cert):
        # MODIFIED: Replaced the old hashing logic with the new robust method.
        # This now uses the same IGNORE_LIST and os.walk logic as cert_util.py,
        # ensuring the hashes will match.
        content_hasher = hashlib.sha256()
        file_count = 0
        for root, dirs, files in os.walk(self.base_path):
            # Modify dirs in place to prevent os.walk from traversing into them
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
                    continue

        if content_hasher.hexdigest() != cert.get('usb_contents_hash'):
            self._handle_validation_failure("Content hash mismatch. The files on the USB have been modified.")
            return False

        if file_count != cert.get('file_count'):
            self._handle_validation_failure(
                f"File count mismatch (Expected {cert.get('file_count')}, found {file_count}).")
            return False
        return True

    def _verify_signature(self, cert, cert_path, sig_path, pub_key_path):
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
            return True
        except Exception as e:
            self._handle_validation_failure(f"Signature verification failed: {e}.")
            return False

    def _handle_validation_failure(self, reason):
        log_usb_activity(self.base_path, "[VALIDATION FAILED]", pasted=f"Reason: {reason}")
        self.stop_file_monitoring()
        self._eject_usb(reason)

    def _eject_usb(self, reason):
        print(f"[{self.drive_letter}:] EJECTING DRIVE. Reason: {reason}")
        log_usb_activity(self.base_path, "[EJECTING]", pasted=f"Reason: {reason}")
        time.sleep(1)
        for attempt in range(1, 4):
            if eject_drive(self.drive_letter):
                log_usb_activity(self.base_path, "[EJECTED]", pasted=f"Ejected on attempt {attempt}")
                print(f"[{self.drive_letter}:] Drive successfully ejected.")
                return
            time.sleep(2)
        log_usb_activity(self.base_path, "[EJECTION FAILED]", pasted="All attempts exhausted")
        print(f"[{self.drive_letter}:] EJECTION FAILED.")


# --- Main Watcher Loop ---
def get_removable_drives():
    return set(p.device.rstrip(':\\') for p in psutil.disk_partitions() if 'removable' in p.opts.lower())


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def main():
    if not is_admin():
        print("This script requires Administrator privileges. Please restart as Admin.")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
        sys.exit(0)

    print("Starting USB Certificate Validator...")
    known_drives = get_removable_drives()
    active_validators = {}

    for drive in known_drives:
        print(f"Found existing drive: {drive}")
        validator = USBCertificateValidator(drive)
        if validator.validate_certificate():
            validator.start_file_monitoring()
            active_validators[drive] = validator

    while True:
        try:
            time.sleep(2)
            current_drives = get_removable_drives()

            newly_inserted = current_drives - known_drives
            for drive in newly_inserted:
                print(f"\n>>> Detected new USB insertion: {drive}:")
                validator = USBCertificateValidator(drive)
                if validator.validate_certificate():
                    validator.start_file_monitoring()
                    active_validators[drive] = validator

            removed_drives = known_drives - current_drives
            for drive in removed_drives:
                print(f"\n<<< USB removed: {drive}:")
                if drive in active_validators:
                    validator = active_validators.pop(drive)
                    validator.stop_file_monitoring()

            known_drives = current_drives
        except KeyboardInterrupt:
            print("\nShutting down all monitors...")
            for validator in active_validators.values():
                validator.stop_file_monitoring()
            print("Shutdown complete.")
            break
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()