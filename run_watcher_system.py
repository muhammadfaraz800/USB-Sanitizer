# run_watcher_system.py
#
# This script is the main entry point for the client-side validation service.
# It runs continuously, handling USB insertions, removals, and drives
# already present on startup. It launches a 'hide_usb_drive.py' worker
# process for each drive and manages the forensic file monitoring.

import time
import psutil
import ctypes
import sys
import os
import subprocess

# --- Core Dependencies & Project Modules ---
try:
    from usb_file_monitor import monitor_usb
except ImportError as e:
    print(f"FATAL: A required library or project file is missing: {e}")
    sys.exit(1)


# --- Helper Functions ---

def get_removable_drives() -> set:
    """Returns a set of drive letters for all currently connected removable drives."""
    try:
        return set(p.device.rstrip(':\\') for p in psutil.disk_partitions() if 'removable' in p.opts)
    except Exception:
        return set()


def is_admin() -> bool:
    """Checks if the script is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# --- Main Application Logic ---

def main():
    """Main function to run the USB watcher service."""
    if not is_admin():
        print("This script requires Administrator privileges. Relaunching as Admin...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
        sys.exit(0)

    print("--- USB Validation Service Started ---")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    worker_script_path = os.path.join(script_dir, "hide_usb_drive.py")

    if not os.path.exists(worker_script_path):
        print(f"FATAL ERROR: The worker script 'hide_usb_drive.py' was not found.")
        print(f"Please ensure it is in the same folder: {script_dir}")
        time.sleep(15)
        sys.exit(1)

    # --- State Management Dictionaries ---
    active_workers = {}
    active_monitors = {}
    drives_in_process = set()
    # MODIFIED: Added a dictionary to track recently processed drives to prevent re-scan loops.
    # The value is a timestamp indicating when the cooldown period started.
    recently_ejected = {}
    EJECTION_COOLDOWN_SECONDS = 15  # Ignore a re-appearing "ghost" drive for 15 seconds.

    print("Watcher is active. Awaiting USB drives...")

    while True:
        try:
            current_drives = get_removable_drives()
            all_known_drives = drives_in_process.union(active_monitors.keys())

            # --- Handle Newly Inserted & Already Connected Drives ---
            drives_to_process = current_drives - all_known_drives
            for drive in sorted(drives_to_process):
                # MODIFIED: Check if the drive is on cooldown to prevent the infinite loop.
                if drive in recently_ejected and (time.time() - recently_ejected[drive]) < EJECTION_COOLDOWN_SECONDS:
                    continue  # This drive letter just re-appeared after ejection. Ignore it.

                print(f"\n>>> New or unprocessed drive detected: {drive}")
                print(f"    Launching validation process for {drive}...")

                cmd = [sys.executable, worker_script_path, drive]
                proc = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
                active_workers[drive] = proc
                drives_in_process.add(drive)

            # --- Check Status of Active Workers ---
            for drive in list(active_workers.keys()):
                proc = active_workers[drive]
                if proc.poll() is not None:
                    print(f"Validation process for drive {drive} has finished.")
                    if proc.returncode == 0:
                        print(f"[{drive}] Validation SUCCESS. Starting forensic monitoring.")
                        observer = monitor_usb(drive)
                        active_monitors[drive] = observer
                    else:
                        print(f"[{drive}] Validation FAILED. Drive was ejected or is inaccessible.")
                        # MODIFIED: Add the failed/ejected drive to the cooldown list.
                        recently_ejected[drive] = time.time()

                    del active_workers[drive]
                    if drive in drives_in_process:
                        drives_in_process.remove(drive)

            # --- Handle Physically Removed Drives ---
            physically_removed_drives = set(active_monitors.keys()) - current_drives
            for drive in sorted(physically_removed_drives):
                print(f"\n<<< Monitored USB drive removed: {drive}")
                observer = active_monitors.pop(drive)
                if observer.is_alive():
                    print(f"    Stopping forensic monitoring for {drive}...")
                    observer.stop()
                    observer.join()

            # --- Prune old entries from the cooldown dictionary ---
            current_time = time.time()
            recently_ejected = {
                drive: ts for drive, ts in recently_ejected.items()
                if (current_time - ts) < EJECTION_COOLDOWN_SECONDS
            }

            time.sleep(2)

        except KeyboardInterrupt:
            print("\nShutting down watcher...")
            for observer in active_monitors.values():
                if observer.is_alive():
                    observer.stop()
                    observer.join()
            for proc in active_workers.values():
                proc.terminate()
            break
        except Exception as e:
            print(f"\nFATAL WATCHER LOOP ERROR: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()
