# usb_logger.py
# === Dev: Rija Fatima ====
# === RIJA: Start - Digital Forensics USB Logging Module ===

import os
import subprocess
from datetime import datetime

def hide_file(filepath):
    """
    Applies Windows hidden, system, and not-content-indexed attributes to a file.
    """
    try:
        subprocess.run(["attrib", "+h", filepath], shell=True)
    except Exception as e:
        print(f"[!] Failed to hide file {filepath}: {e}")

def log_usb_activity(device_name: str, status: str, copied: str = "-", pasted: str = "-", moved: str = "-"):
    """
    Logs USB activity to logs.log in two locations:
    - On the USB itself
    - At C:/Windows/USB_DETECTOR/logs.log
    Also hides both log files using attrib.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = (
        f"\n--- USB FORENSIC LOG ---\n"
        f"TYPE: {status}\n"
        f"DEVICE NAME: {device_name}\n"
        f"TIME: {timestamp}\n"
        f"COPIED: {copied}\n"
        f"PASTED: {pasted}\n"
        f"MOVED/CUTTED: {moved}\n"
        f"---------------------------\n"
    )

    # === Save to C:/Windows/USB_DETECTOR/logs.log ===
    try:
        subprocess.run(["attrib", "+h", "C:/Windows/USB_DETECTOR"], shell=True)
    except Exception as e:
        print(f"[!] Failed to hide folder C:/Windows/USB_DETECTOR: {e}")
    win_dir = "C:/Windows/USB_DETECTOR"
    os.makedirs(win_dir, exist_ok=True)
    win_log_path = os.path.join(win_dir, "logs.log")
    with open(win_log_path, "a") as win_log:
        win_log.write(log_entry)
    hide_file(win_log_path)

    # === Save to USB root (e.g., E:\logs.log) ===
    try:
        usb_log_path = os.path.join(device_name, "logs.log")
        with open(usb_log_path, "a") as usb_log:
            usb_log.write(log_entry)
        hide_file(usb_log_path)
    except Exception as e:
        print(f"[!] Failed to write or hide log on USB: {e}")

# === RIJA: End - Digital Forensics USB Logging Module ===

if __name__ == "__main__":
    log_usb_activity("E:", "copied")
