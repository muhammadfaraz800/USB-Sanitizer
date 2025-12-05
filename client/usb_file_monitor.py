# usb_file_monitor.py
#
# This module provides the real-time "sensor" for file system activity.
# It uses the 'watchdog' library to monitor for file and directory changes
# on a USB drive and forwards those events to the forensic logger.

import os
import time
import sys
# Add parent directory to path to allow importing 'core'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, DirModifiedEvent, FileModifiedEvent

# Import the upgraded forensic logger
try:
    from core.usb_logger import log_usb_activity, get_file_hash
except ImportError:
    # If running from root as a module, or if core isn't found
    from core.usb_logger import log_usb_activity, get_file_hash


class ForensicEventHandler(FileSystemEventHandler):
    """
    Handles file system events and logs them with forensic detail.
    """

    def __init__(self, drive_letter: str):
        self.drive_letter = drive_letter
        self.device_name = f"{drive_letter}:\\"
        self.log_file_name = "logs.log"  # Define log file name to ignore
        # Keep track of the last processed event to avoid some duplicate logs
        self._last_event_key = None
        self._last_event_time = 0

    def _is_duplicate(self, event_key):
        """Prevents logging the exact same event within a 1-second window."""
        current_time = time.time()
        if self._last_event_key == event_key and (current_time - self._last_event_time) < 1:
            return True
        self._last_event_key = event_key
        self._last_event_time = current_time
        return False

    def _is_log_file(self, path: str) -> bool:
        """Checks if the event path is the log file itself."""
        return os.path.basename(path) == self.log_file_name

    def on_any_event(self, event):
        """Catch-all for certain attribute changes that are not explicitly handled."""
        # Ignore events related to the log file itself to prevent a loop
        if self._is_log_file(event.src_path):
            return

        # This can sometimes catch attribute changes on some OS versions.
        # We check if it's a modification event that watchdog didn't route to on_modified.
        if isinstance(event, (DirModifiedEvent, FileModifiedEvent)) and not event.is_directory:
            # This is our custom event type for attribute changes.
            if not self._is_duplicate(f"attrib:{event.src_path}"):
                log_usb_activity(
                    self.device_name,
                    "[FILE ATTRIBUTES MODIFIED]",
                    event_path=event.src_path,
                    file_hash=get_file_hash(event.src_path)
                )

    def on_created(self, event):
        """Called when a file or directory is created."""
        # Ignore events related to the log file itself
        if self._is_log_file(event.src_path):
            return

        if self._is_duplicate(f"create:{event.src_path}"):
            return

        if event.is_directory:
            log_usb_activity(self.device_name, "[DIRECTORY CREATED]", event_path=event.src_path)
        else:
            # For created files, calculate and log the hash.
            file_hash = get_file_hash(event.src_path)
            log_usb_activity(self.device_name, "[FILE CREATED]", event_path=event.src_path, file_hash=file_hash)

    def on_deleted(self, event):
        """Called when a file or directory is deleted."""
        # Ignore events related to the log file itself
        if self._is_log_file(event.src_path):
            return

        if self._is_duplicate(f"delete:{event.src_path}"):
            return
        # We can't hash a deleted file, so we note that in the log.
        if event.is_directory:
            log_usb_activity(self.device_name, "[DIRECTORY DELETED]", event_path=event.src_path,
                             file_hash="N/A (Directory)")
        else:
            log_usb_activity(self.device_name, "[FILE DELETED]", event_path=event.src_path,
                             file_hash="N/A (File Deleted)")

    def on_modified(self, event):
        """Called when a file is modified."""
        # Ignore events related to the log file itself
        if self._is_log_file(event.src_path):
            return

        if self._is_duplicate(f"modify:{event.src_path}"):
            return
        if not event.is_directory:
            # Log the hash of the file *after* modification.
            file_hash = get_file_hash(event.src_path)
            log_usb_activity(self.device_name, "[FILE MODIFIED]", event_path=event.src_path, file_hash=file_hash)

    def on_moved(self, event):
        """Called when a file or directory is moved or renamed."""
        # Ignore events where the source or destination is the log file
        if self._is_log_file(event.src_path) or self._is_log_file(event.dest_path):
            return

        if self._is_duplicate(f"move:{event.src_path}"):
            return

        full_path = f"{event.src_path} -> {event.dest_path}"
        if event.is_directory:
            log_usb_activity(self.device_name, "[DIRECTORY MOVED/RENAMED]", event_path=full_path,
                             file_hash="N/A (Directory)")
        else:
            # A moved file still has a hash.
            file_hash = get_file_hash(event.dest_path)
            log_usb_activity(self.device_name, "[FILE MOVED/RENAMED]", event_path=full_path, file_hash=file_hash)


def monitor_usb(drive_letter: str):
    """
    Initializes and starts the forensic file system monitor on a given drive.

    Returns:
        The observer object, so the calling script can stop it later.
    """
    path = f"{drive_letter}:\\"
    event_handler = ForensicEventHandler(drive_letter)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    print(f"[✓] Forensic monitoring started on {path}")
    return observer


if __name__ == '__main__':
    # Example usage for testing this module directly.
    test_drive = "E"
    print(f"Starting forensic monitor test on drive {test_drive}:\\")
    print("Create, delete, rename, or modify files and folders to see log output.")
    print("Press Ctrl+C to stop.")

    observer = monitor_usb(test_drive)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        observer.stop()
    observer.join()
    print("Monitor stopped.")