# usb_ejector.py

import os
import win32file
import time
import subprocess
import logging

logger = logging.getLogger(__name__)


def is_drive_present(drive_letter):
    return os.path.exists(drive_letter)


def is_removable_drive(drive_letter):
    try:
        return win32file.GetDriveType(drive_letter + ":\\") == win32file.DRIVE_REMOVABLE
    except Exception as e:
        logger.error(f"Error checking drive type: {e}")
        return False


def eject_drive(drive_letter):
    time.sleep(1)

    if not is_drive_present(drive_letter + ":\\"):
        logger.warning(f"Drive {drive_letter}: not found. Skipping eject.")
        return False

    if not is_removable_drive(drive_letter):
        logger.warning(f"Drive {drive_letter}: not removable. Skipping eject.")
        return False

    powershell_command = f'''
$drive = New-Object -comObject Shell.Application
$folder = $drive.Namespace(17)
$item = $folder.ParseName("{drive_letter}:\\")
if ($item -ne $null) {{
    $item.InvokeVerb("Eject")
}} else {{
    Write-Error "Could not find drive {drive_letter} in Shell Namespace."
}}
'''

    try:
        result = subprocess.run(
            ["powershell", "-Command", powershell_command],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            logger.error(f"Eject failed: {result.stderr.strip()}")
            return False

        time.sleep(2)
        if is_drive_present(drive_letter + ":\\"):
            logger.warning(f"Drive {drive_letter} still present. Ejection may have failed.")
            return False
        else:
            logger.info(f"Drive {drive_letter} successfully ejected.")
            return True

    except Exception as e:
        logger.error(f"Exception during ejection: {e}")
        return False
