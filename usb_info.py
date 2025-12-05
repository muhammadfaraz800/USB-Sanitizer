"""
usb_info.py

Provides functions to:
  - List mounted removable drives via psutil (list_removable_drives)
  - Enumerate USB Mass Storage devices via PyUSB (get_usb_storage_devices)
  - Retrieve VID, PID, Serial for those storage devices using WMI (get_usb_storage_devices)
"""
import subprocess
import re
import psutil
import usb.core
import usb.util
import libusb_package

# Configure PyUSB to use the libusb_package backend
# libusb_package handles backend discovery for us when we use its find method




def list_removable_drives():
    """
    Returns a list of dicts for mounted removable drives:
      [{'mountpoint': 'E', 'device': 'E:\'}, ...]
    """
    drives = []
    for part in psutil.disk_partitions():
        if 'removable' in part.opts or 'cdrom' in part.opts:
            mp = part.mountpoint.rstrip('\\:')
            drives.append({
                'mountpoint': mp,
                'device': part.device
            })
    return drives


def get_all_usb_vpd_serials():
    """
    Runs PowerShell to list all USB hub DeviceIDs and parses VID, PID, Serial.
    Returns:
      [{'vid': '0781', 'pid': '5567', 'serial': 'ABC123'}, ...]
    """
    try:
        cmd = [
            'powershell', '-Command',
            r"Get-WmiObject Win32_USBHub | Select-Object -ExpandProperty DeviceID"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = result.stdout.strip().splitlines()
    except subprocess.CalledProcessError:
        return []

    usb_list = []
    pattern = re.compile(r'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})\\(.+)')
    for line in lines:
        m = pattern.search(line)
        if m:
            usb_list.append({
                'vid': m.group(1).lower(),
                'pid': m.group(2).lower(),
                'serial': m.group(3)
            })
    return usb_list


def get_storage_vid_pid_set():
    """
    Uses PyUSB to identify mass storage devices and returns their VID/PID set.
    """
    USB_CLASS_MASS_STORAGE = 0x08
    storage = set()
    # Use libusb_package to find devices which automatically handles the backend
    devices = libusb_package.find(find_all=True)
    if devices is None:
        return storage
    for dev in devices:
        try:
            for cfg in dev:
                for intf in cfg:
                    if intf.bInterfaceClass == USB_CLASS_MASS_STORAGE:
                        storage.add((format(dev.idVendor, '04x'), format(dev.idProduct, '04x')))
                        raise StopIteration
        except usb.core.USBError:
            continue
        except StopIteration:
            continue
    return storage


def get_usb_storage_devices():
    """
    Combines WMI serial info with PyUSB storage filter to return
    only USB storage devices with vid, pid, serial.
    Returns:
      [{'vid': '0781', 'pid': '5567', 'serial': 'ABC123'}, ...]
    """
    all_usb = get_all_usb_vpd_serials()
    storage_set = get_storage_vid_pid_set()
    return [dev for dev in all_usb if (dev['vid'], dev['pid']) in storage_set]


if __name__ == '__main__':
    print(list_removable_drives())
    print(get_usb_storage_devices())