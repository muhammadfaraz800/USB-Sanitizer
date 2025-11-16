# usb_file_monitor.py
# === Dev: Rija Fatima ====
# Monitors file activity (copy, paste, move, delete) on a USB drive
# Requires: watchdog, usb_logger

import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
# MODIFIED: It's better to have Forensics in the path or use relative imports properly.
# Assuming Forensics is a package, this import is fine.
from Forensics.usb_logger import log_usb_activity

LOG_FILE_NAME = "logs.log"


class USBEventHandler(FileSystemEventHandler):
    def __init__(self, drive_letter):
        self.drive_letter = drive_letter
        self.device_name = f"{drive_letter}:\\"

    def on_created(self, event):
        if not event.is_directory and os.path.basename(event.src_path) != LOG_FILE_NAME:
            print(f"Created a file: {event.src_path}")
            log_usb_activity(self.device_name, "[CREATED]", pasted=event.src_path)

    def on_deleted(self, event):
        if not event.is_directory and os.path.basename(event.src_path) != LOG_FILE_NAME:
            print(f"Deleted a file: {event.src_path}")
            log_usb_activity(self.device_name, "[DELETED]", moved=event.src_path)

    def on_moved(self, event):
        if not event.is_directory and os.path.basename(event.src_path) != LOG_FILE_NAME:
            print(f"Moved a file: {event.src_path} to {event.dest_path}")
            log_usb_activity(self.device_name, "[MOVED]", moved=f"{event.src_path} -> {event.dest_path}")

    def on_modified(self, event):
        if not event.is_directory and os.path.basename(event.src_path) != LOG_FILE_NAME:
            print(f"Modified a file: {event.src_path}")
            log_usb_activity(self.device_name, "[MODIFIED]", pasted=event.src_path)


def monitor_usb(drive_letter):
    """
    Start monitoring a USB drive for file activities.
    """
    path = f"{drive_letter}:\\"
    event_handler = USBEventHandler(drive_letter)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    print(f"[✓] Now monitoring {path} for file operations...")

    # MODIFIED: The function now returns the observer object.
    # This allows the calling script (validate_cert.py) to stop the monitor gracefully,
    # which is crucial for making the ejection process robust. Without this, the
    # monitoring process would keep a lock on the drive, preventing ejection.
    return observer


if __name__ == "__main__":
    # Example usage: Monitor E: drive
    observer = monitor_usb("E")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
