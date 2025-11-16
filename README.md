# USB-Sanitizer

USB-Sanitizer is a security tool designed to protect your system from USB-borne threats. It actively monitors for newly connected USB drives, scans them for potential malware, and takes action based on the scan results. If a drive is found to be clean, it is certified with a hardware-bound certificate. If malware is detected, the drive is automatically and forcefully ejected.

## Features

- **Real-time Monitoring:** Continuously watches for the insertion and removal of USB drives.
- **Automated Malware Scanning:** Automatically scans newly inserted USB drives for suspicious files.
- **Forced Ejection:** If malware is detected, the infected USB drive is immediately and forcefully ejected to prevent any potential damage.
- **Hardware-Bound Certificates:** Clean drives are issued a digital certificate, tying them to the specific hardware they were scanned on.
- **Access Control:** During a scan, a drive is set to read-only, and user access is temporarily revoked to prevent interference.

## How It Works

1.  **Detection:** The `usb_watcher.py` script runs in the background, monitoring for any newly connected USB storage devices.
2.  **Lockdown:** When a new drive is detected, `usb_scanner.py` immediately places it in a read-only mode and denies user access.
3.  **Scanning:** The scanner then performs a quick scan, looking for files with extensions commonly associated with malware (e.g., `.exe`, `.vbs`, `.bat`).
4.  **Certification:** If the drive is found to be clean, `cert_util.py` generates a unique, hardware-bound certificate and stores it on the USB drive. Access to the drive is then restored.
5.  **Ejection:** If any suspicious files are found, the drive is not certified. Instead, `usb_ejector.py` is called to forcefully eject the drive. The script will make several attempts to ensure the drive is safely removed.

## How to Use

To start the USB Sanitizer, run the `usb_watcher.py` script with administrator privileges:

```bash
python usb_watcher.py
```

The script will automatically request administrator elevation if it's not already running with it. Once started, it will begin monitoring for USB drives in the background.

## Components

-   **`usb_watcher.py`**: The main script that monitors for USB drive insertions and removals. It orchestrates the scanning and certification process.
-   **`usb_scanner.py`**: Handles the scanning of USB drives. It locks the drive, scans for suspicious files, and restores access if the drive is clean.
-   **`usb_ejector.py`**: Forcefully ejects a USB drive. This is used when malware is detected.
-   **`cert_util.py`**: Manages the creation and validation of hardware-bound certificates for clean drives.
-   **`generate_keys.py`**: A utility script for generating the public/private key pair used for signing the certificates.
-   **`validate_cert.py`**: A utility for validating the certificates on a USB drive.
-   **`usb_info.py`**: A helper script that provides information about connected USB drives.
-   **`Forensics/`**: This directory is likely intended for storing logs or other forensic data, although its exact use is not yet implemented.
