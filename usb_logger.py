# usb_logger.py
#001-2
# This module provides forensically-sound logging capabilities.
# It records detailed events with user and system context, hashes relevant files,
# creates a tamper-evident log chain, and automatically rotates/archives logs.

import os
import sys
import subprocess
import hashlib
import getpass
import socket
from datetime import datetime

# --- Configuration ---
MAX_LOG_SIZE_BYTES = 5 * 1024  # 5 KB
LAST_HASH = None # Global variable to store the hash of the last log entry

def set_hidden_attribute(path: str):
    """
    Applies the Windows 'hidden' attribute to a file or folder.
    This prevents it from showing in normal File Explorer views.
    """
    try:
        # The 'attrib +h' command works on both files and directories.
        # Using CREATE_NO_WINDOW prevents a console from flashing on screen.
        subprocess.run(
            ["attrib", "+h", path],
            check=False,
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except Exception as e:
        # This might fail if permissions are extremely restricted, but should generally work.
        print(f"[!] Warning: Failed to set hidden attribute on {path}: {e}")

def get_log_dir() -> str:
    """
    Returns the secure, user-specific path for storing local logs.
    This avoids permission errors associated with writing to C:\Windows.
    """
    # AppData\Local is the standard location for application-specific data.
    log_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'USBSecurityLogs')
    os.makedirs(log_dir, exist_ok=True)
    set_hidden_attribute(log_dir)
    return log_dir

def get_file_hash(file_path: str) -> str:
    """Calculates and returns the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read and update hash in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, PermissionError):
        return "Could not read file (access denied or locked)"

def set_archive_attributes(filepath: str):
    """Applies hidden and read-only attributes to a sealed log archive."""
    try:
        # Using CREATE_NO_WINDOW to prevent a console window from flashing.
        subprocess.run(
            ["attrib", "+h", "+r", filepath],
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except Exception as e:
        print(f"[!] Failed to set archive attributes on {filepath}: {e}")

def rotate_log_if_needed(log_path: str):
    """Checks log size and rotates the file if it exceeds the max size."""
    global LAST_HASH
    if not os.path.exists(log_path) or os.path.getsize(log_path) < MAX_LOG_SIZE_BYTES:
        return

    print(f"Log file size exceeds {MAX_LOG_SIZE_BYTES / 1024} KB. Archiving...")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    archive_path = os.path.join(get_log_dir(), f"log_archive_{timestamp}.log")

    try:
        os.rename(log_path, archive_path)
        set_archive_attributes(archive_path)
        print(f"Log archived to: {archive_path}")
        # Reset the hash chain for the new log file.
        LAST_HASH = None
    except Exception as e:
        print(f"Error rotating log file: {e}")

def log_usb_activity(device_name: str, status: str, event_path: str = "-", file_hash: str = "-"):
    """
    Logs USB activity with comprehensive forensic details.

    Args:
        device_name (str): The device being monitored (e.g., 'E:\\').
        status (str): The type of event (e.g., '[FILE CREATED]').
        event_path (str): The path associated with the event.
        file_hash (str): The SHA-256 hash of the file, if applicable.
    """
    global LAST_HASH
    log_dir = get_log_dir()
    local_log_path = os.path.join(log_dir, "logs.log")

    # Check for rotation before we do anything else.
    rotate_log_if_needed(local_log_path)

    # If the in-memory hash is lost (e.g., script restart), re-read it from the log file.
    # This block is the primary change.
    if LAST_HASH is None and os.path.exists(local_log_path):
        try:
            with open(local_log_path, 'r') as f:
                lines = f.readlines()
                # Search backwards from the end of the file for the last valid hash.
                for line in reversed(lines):
                    if line.strip().startswith("Current Log Hash:"):
                        LAST_HASH = line.split(":", 1)[1].strip()
                        break
        except Exception as e:
            # If any error occurs, the chain will start fresh.
            print(f"[!] Could not re-initialize hash chain from log file: {e}")
            LAST_HASH = None # Ensure it's None so it gets the default zero-hash below

    # Build the detailed log entry
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    username = getpass.getuser()
    hostname = socket.gethostname()

    # Use the found hash, or default to a string of zeros if no previous hash exists.
    previous_hash = LAST_HASH or "0" * 64

    log_data = [
        f"Timestamp: {timestamp}",
        f"Username: {username}",
        f"Hostname: {hostname}",
        f"Event Type: {status}",
        f"Device Name: {device_name}",
        f"Event Path: {event_path}",
        f"File SHA-256: {file_hash}",
        f"Previous Log Hash: {previous_hash}"
    ]

    # Calculate the hash of this new entry (before adding the hash itself)
    entry_for_hashing = "\n".join(log_data)
    current_hash = hashlib.sha256(entry_for_hashing.encode()).hexdigest()
    log_data.append(f"Current Log Hash: {current_hash}")

    # Finalize the log entry with a clear structure
    log_entry = (
        f"\n--- FORENSIC LOG ENTRY ---\n"
        + "\n".join(log_data)
        + "\n--------------------------\n"
    )

    # Write to the local log file
    try:
        with open(local_log_path, "a") as f:
            f.write(log_entry)
        # Update the global hash for the next write operation.
        LAST_HASH = current_hash
    except Exception as e:
        print(f"[!] Failed to write to local log at {local_log_path}: {e}")

    # === Save to USB root (e.g., E:\logs.log) ===
    try:
        usb_log_path = os.path.join(device_name, "logs.log")
        with open(usb_log_path, "a") as usb_log:
            usb_log.write(log_entry)
        set_hidden_attribute(usb_log_path)
    except Exception as e:
        print(f"[!] Failed to write or hide log on USB: {e}")