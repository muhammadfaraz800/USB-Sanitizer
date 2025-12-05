# USB Sanitizer & Guardian

**USB Sanitizer** is a secure, automated tool designed to protect Windows systems from malicious USB drives. It continuously monitors for new USB connections, locks them locally to prevent unauthorized access or execution of malware, scans them for threats, and generates a digital certificate for safe, clean drives.

![USB Guardian Look](https://via.placeholder.com/800x400?text=USB+Guardian+GUI+Preview)

## 🚀 Features

- **Real-Time Monitoring**: Automatically detects when a USB drive is inserted.
- **Instant Lockdown**: Immediately mounts new drives as **Read-Only** and denies user access to prevent auto-run malware.
- **Automated Scanning**:
  - Identifies and scans potentially dangerous file types (`.exe`, `.bat`, `.vbs`, etc.).
  - Calculates file hashes (SHA-256) for verification.
- **Threat Mitigation**:
  - If threats are found, the drive remains locked and the system attempts to safely eject it.
- **Digital Certification**:
  - For clean drives, it generates a cryptographically signed `usb_certificate.json` stored on the drive.
  - Verifies the integrity of the drive's contents against this certificate on subsequent connections.
- **Modern GUI**: A dark-themed, responsive interface built with `customtkinter`.

## 🛠️ Prerequisites

- **OS**: Windows 10/11 (Required for `diskpart`, `icacls`, and PowerShell interactions).
- **Python**: 3.8 or higher.
- **Admin Privileges**: The application must run as Administrator to control disk attributes and permissions.

## 📦 Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Start-ignite/USB-Sanitizer.git
    cd USB-Sanitizer
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```
    *Note: This will install `customtkinter`, `psutil`, `pyusb`, `cryptography`, `libusb-package`, and others.*

## 🖥️ Usage

1.  **Run the Application**
    Open a terminal as **Administrator** and run:
    ```bash
    python gui.py
    ```
    *If you strictly run it without admin rights, the script will attempt to auto-elevate itself, prompting a UAC dialog.*

2.  **Workflow**
    - **Connect a USB**: The app detects it and shows "Scanning...".
    - **Wait**: The drive is locked. The app checks for dangerous files.
    - **Clean Drive**: Status changes to "Clean". You can now click **"Generate Certificate"** (if configured) or simply use the drive.
    - **Infected Drive**: Status changes to "Infected". The app constantly tries to eject it to protect your PC.

## 📂 Project Structure

- `gui.py`: Main entry point. Handles the UI and background worker thread.
- `usb_scanner.py`: Logic for locking drives (`diskpart`), changing permissions (`icacls`), and scanning files.
- `cert_util.py`: Handles cryptographic operations, hashing file contents, and signing certificates.
- `usb_info.py` & `usb_ejector.py`: Helpers for gathering USB metadata and safely ejecting drives.
- `generate_keys.py`: Generates the RSA private/public key pair used for signing certificates (stored in `C:\Windows\private_key.pem`).

## ⚠️ Disclaimer

This tool interacts with low-level system commands (`diskpart`, `icacls`) to modify drive attributes. While designed to be safe:
- **Always backup important data.**
- Use at your own risk. The authors are not responsible for data loss or system instability.

---
*Built for Information Security End Semester Project.*
