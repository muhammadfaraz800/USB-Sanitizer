"""
This file will generate the key pairs using RSA Algorithm
Private key -> Encryption
Public key -> Decryption
"""
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from usb_info import list_removable_drives

def generate_key_pair():
    # Generate a new private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    """
    Serialize and save the private key to a file.
    This file must be kept secret and secure on the computer running the scanner.
    """

    # --- PATH: Define the path for the private key in C:\Windows ---
    private_key_path = os.path.join('C:\\', 'Windows', 'private_key.pem')
    try:
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print("✅ private_key.pem and public_key.pem created.")
        print(f"✅ private_key.pem successfully saved to: {private_key_path}")
    except PermissionError:
        print(f"❌ PERMISSION DENIED: Could not write to {private_key_path}.")
        print("   Please run this script as an Administrator.")
    except Exception as e:
        print(f"❌ An error occurred while saving the private key: {e}")
    # Get the public key from the private key
    public_key = private_key.public_key()

    """
    Save the public key to a file on a USB drive.
    """
    # --- Get removable drives ---
    removable_drives = list_removable_drives()

    if not removable_drives:
        print("\n❌ No USB drives detected. The public key cannot be saved to a USB drive.")
        print("✅ private_key.pem has been created. Please insert a USB and run this script again to save the public_key.pem.")

    else:
        # --- Save public key to each detected USB Drive ---
        print(f"\nFound {len(removable_drives)} USB drive(s). Saving public key...")
        for drive in removable_drives:
            drive_letter = drive["mountpoint"]
            public_key_path = os.path.join(f"{drive_letter}:\\", "public_key.pem")
            try:
                with open(public_key_path, "wb") as f:
                    f.write(public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                print(f"✅ public_key.pem successfully saved to: {public_key_path}")
            except Exception as e:
                print(f"❌ An error occurred while saving the public key to {public_key_path}: {e}")

    print("🔒 IMPORTANT: Keep your private_key.pem file secret!")


if __name__ == "__main__":
    generate_key_pair()