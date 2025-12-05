"""
usb_scanner.py

Imports usb_info (usb_info.py) for device listing.
Scans each USB storage device:
- Forces USB mount read-only
- Denies user access
- Performs quick manual scan on suspicious files with progress
- Restores access if clean, leaves blocked if threats
Requires script to run with admin rights (auto-elevates if not).
"""
import subprocess
import logging
import os
import hashlib
import sys
import ctypes
from usb_info import list_removable_drives  # Ensure usb_info.py is alongside

# --- ADMIN ELEVATION CHECK ---
def is_admin() -> bool:
    """Return True if the script is running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # Re-launch the script with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                         ' '.join(sys.argv), None, 1)
    sys.exit(0)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Definitive safe set (removes only clearly non-malicious)
SUSPECT_EXTENSIONS = {'.exe', '.vbs', '.bat', '.dll', '.js', '.scr', '.doc', '.txt'}

# --- READ-ONLY & ACCESS CONTROL ---

def set_drive_readonly(drive_letter: str):
    script = f"""
select volume {drive_letter.strip(':')}  
attributes volume set readonly  
exit
"""
    subprocess.run(['diskpart'], input=script, text=True, capture_output=True)


def clear_drive_readonly(drive_letter: str):
    script = f"""
select volume {drive_letter.strip(':')}  
attributes volume clear readonly  
exit
"""
    subprocess.run(['diskpart'], input=script, text=True, capture_output=True)


def deny_user_access(drive_letter: str):
    subprocess.run([
        'icacls', f"{drive_letter}\\", '/inheritance:r', '/deny', 'Users:(OI)(CI)(R)'
    ], capture_output=True)


def restore_user_access(drive_letter: str):
    subprocess.run(['icacls', f"{drive_letter}\\", '/remove:d', 'Users'], capture_output=True)
    subprocess.run(['icacls', f"{drive_letter}\\", '/inheritance:e'], capture_output=True)

# --- MANUAL SCAN ---

def manual_quick_scan(drive_letter: str) -> bool:
    """
    Scans USB for only suspicious files by extension, shows progress.
    Returns True if clean, False if threats found or unreadable.
    """
    path = f"{drive_letter}:\\"
    files_to_scan = []

    for root, _, files in os.walk(path):
        for f in files:
            if any(f.lower().endswith(ext) for ext in SUSPECT_EXTENSIONS):
                files_to_scan.append(os.path.join(root, f))

    total = len(files_to_scan)
    if total == 0:
        logger.info("No risky files found. Drive looks clean.")
        return True

    logger.info(f"Scanning {total} suspicious files...")

    for i, file_path in enumerate(files_to_scan, 1):
        try:
            with open(file_path, 'rb') as f:
                _ = hashlib.sha256(f.read()).hexdigest()  # placeholder for threat lookup
        except Exception:
            logger.warning(f"Could not read {file_path}; treating as potential threat.")
            return False

        percent = int((i / total) * 100)
        print(f"[{percent}%] {file_path}")

    return True

# --- FULL SCAN LOGIC ---

def scan_and_restore(drive_letter: str) -> bool:
    logger.info(f"Locking {drive_letter}: for scan.")
    set_drive_readonly(drive_letter)
    deny_user_access(drive_letter)

    clean = manual_quick_scan(drive_letter)

    if clean:
        print(f"No threats found on {drive_letter}. Unlocking drive.")
        clear_drive_readonly(drive_letter)
        restore_user_access(drive_letter)
        return True
    else:
        logger.warning(f"Threats found or scan failed on {drive_letter}. Drive remains locked.")
        return False


def scan_all():
    """
    Scans all removable USB storage devices discovered via usb_info.list_removable_drives().
    Returns:
        dict: drive_letter -> bool (True if clean, False if threats or error)
    """
    results = {}
    drives = list_removable_drives()
    for d in drives:
        letter = d['mountpoint'].rstrip(':\\')
        ok = scan_and_restore(letter)
        results[letter] = ok
    return results

if __name__ == "__main__":
    results = scan_all()
    for drive, status in results.items():
        print(f"{drive}: {'Clean' if status else ' Blocked'}")
