"""
usb_watcher.py

Real-time USB detection and malware scan:
- On startup, scans all currently plugged USB storage drives.
- Watches for USB insertion/removal, rescanning on insert.
- If malware detected, forcibly ejects USB volume (with retries).
- If clean, generates and stores certificate on the USB.

Requires:
- usb_scanner.scan_and_restore(drive_letter)
- cert_util.generate_and_store_cert(drive_letter) [optional]
- usb_ejector.eject_drive(drive_letter)
- Run as Administrator
"""


# Main file of Admin side program
import time
import logging
import psutil
import ctypes
import sys
# MODIFIED: Imported the unlock functions from the scanner.
# We need these to make the drive writable before attempting to eject it.
from usb_scanner import scan_and_restore, clear_drive_readonly, restore_user_access
from usb_ejector import eject_drive
from cert_util import generate_and_store_cert

# --- ADMIN ELEVATION CHECK ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                         ' '.join(sys.argv), None, 1)
    sys.exit(0)

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def get_removable_drives():
    """
    Return set of drive letters (e.g., {'E', 'F'}) for removable USB volumes.
    """
    return set(p.device.rstrip(':\\') for p in psutil.disk_partitions()
               if 'removable' in p.opts.lower())


# MODIFIED: This function is now more robust.
# It will first attempt to unlock the drive from the read-only state
# that the scanner leaves it in, which greatly increases the chance of a
# successful ejection.
def try_eject_with_retries(drive, retries=5, delay=3):
    """
    Attempt to eject the USB drive up to `retries` times with `delay` seconds between.
    It first unlocks the drive to release any locks from the scanner.
    Returns True if ejected, False otherwise.
    """
    logger.info(f"Unlocking drive {drive}: to prepare for ejection.")
    clear_drive_readonly(drive)
    restore_user_access(drive)
    time.sleep(1) # Give a moment for the system to process the attribute changes.

    for attempt in range(1, retries + 1):
        logger.info(f"Eject attempt {attempt}/{retries} for {drive}:")
        if eject_drive(drive):
            logger.info(f"✅ Drive {drive}: successfully ejected.")
            return True
        time.sleep(delay)

    logger.warning(f"Failed to eject {drive} after {retries} attempts.")
    return False


def initial_scan(drives):
    """
    Scan all drives present at startup.
    """
    for drive in drives:
        logger.info(f"Initial scan of existing USB: {drive}:")
        clean = scan_and_restore(drive)

        if clean:
            print(f"Existing USB {drive} is clean.")
            print("Saving certificate to the USB")
            generate_and_store_cert(drive)
        else:
            logger.warning(f"Threats found on {drive}. Drive has been locked.")
            logger.info(f"Attempting to eject {drive}.")
            try_eject_with_retries(drive)

# case if usb is already connected to the system
def watch_usb():
    logger.info("Starting USB watcher...")
    known = get_removable_drives() # a set of drive letter of connected usb storage devices
    if known: # if set is not empty
        initial_scan(known)

    while True:
        time.sleep(2)
        current = get_removable_drives() #previously connected USBs
        # New insertions
        for drive in sorted(current - known):
            logger.info(f"Detected new USB insertion: {drive}:")
            clean = scan_and_restore(drive)
            if clean:
                print(f"Inserted USB {drive} is clean.")
                print("Saving Certificate to USB...")
                generate_and_store_cert(drive)
            else:
                logger.warning(f"Threats found on {drive}. Drive has been locked.")
                logger.info(f"Attempting to eject {drive}.")
                try_eject_with_retries(drive)
        # Removals
        for drive in sorted(known - current):
            logger.info(f"USB removed: {drive}:")
        known = current

if __name__ == '__main__':
    watch_usb()
