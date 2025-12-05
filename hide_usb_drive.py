# hide_usb_drive.py
#
# This script is the "worker" process. It handles the entire sandboxing
# and validation for a SINGLE drive and is launched by run_watcher_system.py.
# Its responsibilities are:
#   1. Wait for the specified drive to be fully initialized by the OS.
#   2. Hide the drive by removing its letter and mounting it to a hidden folder.
#   3. Perform certificate validation on the sandboxed contents.
#   4. Clean up the sandbox and ALWAYS restore the original drive letter.
#   5. Eject the drive if validation fails.
#   6. Exit with code 0 on success or 1 on failure.

import os
import sys
import time
import subprocess

# --- Core Dependencies & Project Modules ---
try:
    import win32file
    from usb_ejector import eject_drive
    from usb_logger import log_usb_activity
    # The USBCertificateValidator class contains the core validation logic.
    from validate_cert import USBCertificateValidator
except ImportError as e:
    print(f"FATAL: A required library or project file is missing: {e}")
    # Exit with a non-zero code to indicate a critical setup failure.
    sys.exit(1)

# --- Sandboxing Functions ---

def get_volume_guid(drive_letter: str) -> str:
    """Waits patiently for a drive to be ready and returns its GUID."""
    print(f"[{drive_letter}] Waiting for drive to initialize...")
    for _ in range(10): # Try for 5 seconds
        letter_with_slash = f"{drive_letter}:\\"
        if os.path.exists(letter_with_slash):
            try:
                guid = win32file.GetVolumeNameForVolumeMountPoint(letter_with_slash)
                print(f"[{drive_letter}] Drive ready. GUID found.")
                return guid
            except win32file.error:
                pass
        time.sleep(0.5)
    print(f"[{drive_letter}] CRITICAL: Could not get Volume GUID after 5 seconds. Aborting.")
    return None

def mount_to_folder(volume_guid: str, mount_folder: str) -> bool:
    """Mounts a volume to a hidden folder."""
    try:
        os.makedirs(mount_folder, exist_ok=True)
        win32file.SetVolumeMountPoint(mount_folder + "\\", volume_guid)
        subprocess.run(
            ["attrib", "+s", "+h", mount_folder],
            check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        return True
    except Exception as e:
        print(f"Error mounting to sandbox folder {mount_folder}: {e}")
        return False

def unmount_from_folder(mount_folder: str) -> bool:
    """Unmounts a volume from a folder and cleans up."""
    try:
        if os.path.exists(mount_folder):
            win32file.DeleteVolumeMountPoint(mount_folder + "\\")
            try:
                os.rmdir(mount_folder)
            except OSError:
                pass
        return True
    except Exception as e:
        print(f"Error unmounting from sandbox folder {mount_folder}: {e}")
        return False

def change_drive_letter(volume_guid: str, drive_letter: str) -> bool:
    """Restores a drive letter to a volume."""
    try:
        win32file.SetVolumeMountPoint(drive_letter + ":\\", volume_guid)
        return True
    except Exception as e:
        print(f"Error restoring drive letter {drive_letter}: {e}")
        return False

def remove_drive_letter(drive_letter: str) -> bool:
    """Removes a drive's letter to make it invisible."""
    try:
        win32file.DeleteVolumeMountPoint(drive_letter + ":\\")
        return True
    except Exception as e:
        print(f"Error removing drive letter {drive_letter}: {e}")
        return False

# --- Main Workflow ---

def process_drive(drive_letter: str) -> bool:
    """
    Executes the entire hide-validate-restore workflow for a single drive.
    Returns True on success, False on failure.
    """
    guid = None
    temp_mount = f"C:\\usb_validation_temp\\{drive_letter}"
    is_valid = False

    try:
        guid = get_volume_guid(drive_letter)
        if not guid:
            return False

        if not remove_drive_letter(drive_letter):
            return False

        if not mount_to_folder(guid, temp_mount):
            change_drive_letter(guid, drive_letter)
            return False

        # Allow time for the mount to be fully recognized
        time.sleep(2)

        validator = USBCertificateValidator(drive_letter)
        validator.base_path = temp_mount + "\\"
        is_valid = validator.validate_certificate()

    except Exception as e:
        print(f"[{drive_letter}] A critical error occurred during validation: {e}")
        is_valid = False

    finally:
        # This block ALWAYS runs, ensuring the drive is not left in a ghost state.
        print(f"[{drive_letter}] Cleaning up sandbox environment...")
        unmount_from_folder(temp_mount)
        if guid:
            print(f"[{drive_letter}] Restoring original drive letter...")
            if not change_drive_letter(guid, drive_letter):
                 print(f"[{drive_letter}] FATAL: Could not restore drive letter.")
                 is_valid = False
        else:
            print(f"[{drive_letter}] No GUID captured; cannot restore drive letter.")
            return False

    # This logic now runs AFTER the 'finally' block has guaranteed the drive letter is restored.
    time.sleep(1)
    if not is_valid:
        print(f"[{drive_letter}] Validation FAILED. Ejecting drive.")
        log_usb_activity(f"{drive_letter}:\\", "[VALIDATION FAILED]", "Ejecting invalid drive.")
        ejected = False
        for _ in range(3):
            if eject_drive(drive_letter):
                print(f"[{drive_letter}] Ejected successfully.")
                ejected = True
                break
            time.sleep(2)
        if not ejected:
            print(f"[{drive_letter}] Ejection failed.")
    else:
        print(f"[{drive_letter}] Validation successful. Access granted.")

    return is_valid

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python hide_usb_drive.py <drive_letter>")
        sys.exit(1)

    drive_letter_arg = sys.argv[1].upper().rstrip(':\\')
    if process_drive(drive_letter_arg):
        sys.exit(0)
    else:
        sys.exit(1)
