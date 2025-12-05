# USB Sanitizer & Guardian

**USB Sanitizer** is a comprehensive security suite designed to protect organizations from malicious USB drives. It consists of two main components:
1.  **Admin Station (GUI)**: A centralized kiosk/station where all USBs must be scanned, sanitized, and certified before use.
2.  **Client Watcher (Background Service)**: A lightweight agent installed on every employee endpoint that enforces the use of certified USBs only.

### 📸 Gallery

![USB Guardian Interface](assets/usb_sanitizer_main.png)
*The Admin Station Interface for scanning and certifying drives.*

![USB Guardian Alert](assets/usb_sanitizer_action.png)
*The Client System blocking/ejecting an uncertified drive.*

---

## 🚀 Features

### 🛡️ Admin Station (The Sanitizer)
- **Real-Time Monitoring**: Automatically detects when a USB drive is inserted.
- **Instant Lockdown**: Immediately mounts new drives as **Read-Only** and denies user access to prevent auto-run malware.
- **Automated Scanning**:
  - Identifies and scans potentially dangerous file types (`.exe`, `.bat`, `.vbs`, etc.).
  - Calculates file hashes (SHA-256) for verification.
- **Digital Certification**:
  - For clean drives, it generates a cryptographically signed `usb_certificate.json` stored on the drive.
  - Verification includes hardware ID locking (VID/PID/Serial) and content integrity checks.

### 🔒 Client Watcher (The Enforcer)
- **Continuous Background Monitoring**: Runs silently on client machines (`run_watcher_system.py`).
- **Certificate Verification**:
  - When *any* USB is plugged in, it immediately reads the `usb_certificate.json`.
  - It validates the cryptographic signature using the organization's public key.
  - It ensures the certificate has not expired.
- **Automatic Ejection**:
  - If a USB is **uncertified**, **modified** after certification, or has an **expired** certificate, it is **immediately ejected**.
  - Prevents users from using unchecked drives on secure systems.

## 🛠️ Prerequisites

- **OS**: Windows 10/11 (Required for `diskpart`, `icacls`, and PowerShell interactions).
- **Python**: 3.8 or higher.
- **Admin Privileges**: Both the GUI and the Client Watcher must run as Administrator.

## 📦 Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/muhammadfaraz800/USB-Sanitizer.git
    cd USB-Sanitizer
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

## 🖥️ Usage

### 1. Admin Station (Sanitizing USBs)
Use this on your dedicated security kiosk.
```bash
python gui.py
```
- **Workflow**: Plugin USB -> Wait for Scan -> If Clean, Click "Generate Certificate".

### 2. Client System (Protecting Endpoints)
Deploy this on all employee/client machines.
```bash
python run_watcher_system.py
```
- **Behavior**: It will sit in the background. If anyone plugs in a USB that hasn't been certified by the Admin Station, it will be rejected and ejected instantly.

## 📂 Project Structure

- `gui.py`: **Admin Dashboard**. Handles scanning, locking, and signing certificates.
- `run_watcher_system.py`: **Client Service**. Monitors for USBs and enforces certificate validity.
- `hide_usb_drive.py`: Worker script used by the watcher to hide/validate drives.
- `cert_util.py`: Shared core for cryptographic operations (signing & verifying).
- `usb_scanner.py`: Logic for drive locking and malware scanning.
- `generate_keys.py`: Generates the RSA Key Pair (`private_key.pem` for Admin, `public_key.pem` for Clients).

## ⚠️ Disclaimer

This tool interacts with low-level system commands (`diskpart`, `icacls`) to modify drive attributes. While designed to be safe:
- **Always backup important data.**
- Use at your own risk. The authors are not responsible for data loss or system instability.

---
*Built for Information Security End Semester Project.*
