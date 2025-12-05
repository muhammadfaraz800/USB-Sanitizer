import customtkinter as ctk
import threading
import queue
import time
import os
import sys
import ctypes
import psutil

# -------------------------------------------------------------------
# IMPORTANT:
# This GUI application assumes that all your original .py files,
# including the MODIFIED cert_util.py, are in the same directory.
# -------------------------------------------------------------------

# --- Backend Logic (Refactored from your scripts) ---
try:
    from usb_info import list_removable_drives, get_usb_storage_devices
    from usb_scanner import scan_and_restore, clear_drive_readonly, restore_user_access
    from usb_ejector import eject_drive
    # This now imports from your MODIFIED cert_util.py
    from cert_util import generate_and_store_cert as backend_gen_cert
    from generate_keys import generate_key_pair
except ImportError as e:
    print(f"CRITICAL ERROR: Failed to import a required module: {e}")
    print("Please ensure all project .py files are in the same directory as this GUI script.")


    # Create dummy functions so the GUI can at least start and show the error
    def list_removable_drives():
        return []


    def get_usb_storage_devices():
        return []


    def scan_and_restore(drive):
        return False


    def eject_drive(drive):
        return False


    def backend_gen_cert(drive, days):
        pass


    def generate_key_pair():
        pass


    def clear_drive_readonly(drive):
        pass


    def restore_user_access(drive):
        pass


class BackendWorker(threading.Thread):
    """
    Runs the USB watching and processing logic in a background thread
    to prevent the GUI from freezing.
    """

    def __init__(self, gui_queue):
        super().__init__(daemon=True)
        self.gui_queue = gui_queue
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def log(self, message):
        """Puts a log message into the queue for the GUI."""
        self.gui_queue.put({'type': 'log', 'message': message})

    def update_drive_status(self, drive, status, name=None):
        """Puts a drive status update into the queue."""
        self.gui_queue.put({
            'type': 'status_update',
            'drive': drive,
            'status': status,
            'name': name
        })

    def request_cert_generation(self, drive, device_info=None):
        """Puts a request to open the certificate modal into the queue."""
        self.gui_queue.put({'type': 'request_cert', 'drive': drive, 'device_info': device_info})

    def increment_counter(self, counter_name, amount=1):
        """Tells the GUI to increment a counter."""
        self.gui_queue.put({'type': 'increment_counter', 'counter': counter_name, 'amount': amount})

    def try_eject_with_retries(self, drive, retries=3, delay=4):
        """
        FIXED: Attempt to eject the USB drive with retries, unlocking it first.
        Returns True if ejected, False otherwise.
        """
        try:
            self.log(f"Unlocking drive {drive}: to prepare for ejection.")
            clear_drive_readonly(drive)
            restore_user_access(drive)
            time.sleep(2)  # Give a moment for the system to process attribute changes.
        except Exception as e:
            self.log(f"ERROR unlocking drive {drive}: {e}. Ejection may fail.")

        for attempt in range(1, retries + 1):
            if self._stop_event.is_set():
                self.log("Ejection cancelled; application is closing.")
                return False

            self.log(f"Eject attempt {attempt}/{retries} for {drive}:")
            if eject_drive(drive):
                self.log(f"✅ Drive {drive}: successfully ejected.")
                return True

            if attempt < retries:
                self.log(f"Attempt {attempt} failed. Retrying in {delay} seconds...")
                time.sleep(delay)

        self.log(f"❌ Failed to eject {drive}: after {retries} attempts.")
        return False

    def run(self):
        """The main loop for the backend thread."""
        self.log("Backend worker started. Monitoring for USB drives...")

        private_key_path = os.path.join('C:\\', 'Windows', 'private_key.pem')
        if not os.path.exists(private_key_path):
            self.log("Private key not found. Generating new key pair...")
            try:
                generate_key_pair()
                self.log("Successfully generated and saved key pair.")
            except Exception as e:
                self.log(f"ERROR: Could not generate keys. Run as Admin. Details: {e}")

        known_drives = set()

        while not self._stop_event.is_set():
            try:
                current_drives_info = {p.device.rstrip(':\\'): p for p in psutil.disk_partitions() if
                                       'removable' in p.opts}
                current_drives = set(current_drives_info.keys())

                newly_inserted = current_drives - known_drives
                if newly_inserted:
                    usb_devices = get_usb_storage_devices()

                for drive in newly_inserted:
                    self.log(f"New USB drive detected: {drive}:")
                    self.increment_counter('connected')

                    found_device_info = None
                    drive_name = "Unknown USB Device"
                    for dev in usb_devices:
                        drive_name = f"{dev.get('vid', '-')}:{dev.get('pid', '-')} {dev.get('serial', '')}"
                        found_device_info = dev
                        break

                    self.update_drive_status(drive, 'scanning', name=drive_name)

                    is_clean = scan_and_restore(drive)

                    if is_clean:
                        self.log(f"Drive {drive}: is clean. Awaiting certificate generation.")
                        self.update_drive_status(drive, 'clean_pending_cert')
                        self.request_cert_generation(drive, found_device_info)
                    else:
                        self.log(f"Threats found on {drive}:. Locking and attempting to eject.")
                        self.update_drive_status(drive, 'infected')

                        # --- FIXED: Call retry function and only increment counter on success ---
                        if self.try_eject_with_retries(drive):
                            self.increment_counter('ejected')
                        else:
                            self.log(f"DRIVE {drive}: REMAINS CONNECTED. EJECTION FAILED.")
                        # --- END OF FIX ---

                removed_drives = known_drives - current_drives
                for drive in removed_drives:
                    self.log(f"USB drive removed: {drive}:")
                    self.gui_queue.put({'type': 'drive_removed', 'drive': drive})

                known_drives = current_drives
                time.sleep(2)

            except Exception as e:
                self.log(f"ERROR in backend loop: {e}")
                time.sleep(5)


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- App State ---
        self.gui_queue = queue.Queue()
        self.backend_thread = None
        self.drive_widgets = {}

        # --- Window Configuration ---
        self.title("USB Guardian")
        self.geometry("900x600")
        self.configure(fg_color="#1D1D1D")
        self.resizable(False, False)

        self.font = ("Segoe UI", 13)

        # --- Main Layout ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # 1. Top Bar
        self.top_bar = ctk.CTkFrame(self, fg_color="transparent")
        self.top_bar.grid(row=0, column=0, padx=20, pady=(10, 0), sticky="ew")

        self.title_label = ctk.CTkLabel(self.top_bar, text="USB Guardian", font=("Segoe UI Semibold", 20))
        self.title_label.pack(side="left")

        self.status_indicator = ctk.CTkLabel(self.top_bar, text="● Monitoring: Active", text_color="#32CD32",
                                             font=self.font)
        self.status_indicator.pack(side="right")

        # 2. Summary Cards
        self.summary_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.summary_frame.grid(row=1, column=0, padx=20, pady=15, sticky="ew")
        self.summary_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.connected_card = self.create_summary_card("Connected Drives", "0")
        self.connected_card.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        self.certified_card = self.create_summary_card("Certified Drives", "0")
        self.certified_card.grid(row=0, column=1, padx=10, sticky="ew")
        self.ejected_card = self.create_summary_card("Ejected Drives", "0")
        self.ejected_card.grid(row=0, column=2, padx=(10, 0), sticky="ew")

        # 3. Main Content Area
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        self.create_drive_list_panel()
        self.create_log_panel()

        # --- Start Backend and GUI Loop ---
        self.start_backend()
        self.process_gui_queue()

    def create_summary_card(self, title, value):
        card = ctk.CTkFrame(self.summary_frame, fg_color="#2B2B2B", corner_radius=8)
        label = ctk.CTkLabel(card, text=title, font=self.font, text_color="#A0A0A0")
        label.pack(pady=(10, 0))
        value_label = ctk.CTkLabel(card, text=value, font=("Segoe UI Bold", 28))
        value_label.pack(pady=(0, 10))
        card.value_label = value_label
        return card

    def create_drive_list_panel(self):
        panel = ctk.CTkFrame(self.main_frame, fg_color="#2B2B2B", corner_radius=8)
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        panel.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(panel, text="Connected USB Drives", font=("Segoe UI Semibold", 16))
        title.pack(pady=10, padx=15, anchor="w")

        self.drive_list_frame = ctk.CTkFrame(panel, fg_color="transparent")
        self.drive_list_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def create_log_panel(self):
        panel = ctk.CTkFrame(self.main_frame, fg_color="#2B2B2B", corner_radius=8)
        panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        panel.grid_rowconfigure(1, weight=1)
        panel.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(panel, text="Live Event Log", font=("Segoe UI Semibold", 16))
        title.grid(row=0, column=0, pady=10, padx=15, sticky="w")

        self.log_textbox = ctk.CTkTextbox(panel, wrap="word", font=self.font, fg_color="#1D1D1D", border_width=0)
        self.log_textbox.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        self.log_textbox.configure(state="disabled")

    def add_log_message(self, message):
        timestamp = time.strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}\n"
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", full_message)
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

    def start_backend(self):
        if not self.is_admin():
            self.add_log_message("WARNING: Not running as Administrator. Please restart with admin rights.")
        else:
            self.add_log_message("Application running with Administrator privileges.")

        self.backend_thread = BackendWorker(self.gui_queue)
        self.backend_thread.start()

    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def process_gui_queue(self):
        try:
            while not self.gui_queue.empty():
                msg = self.gui_queue.get(0)

                if msg['type'] == 'log':
                    self.add_log_message(msg['message'])
                elif msg['type'] == 'status_update':
                    self.update_drive_ui(msg['drive'], msg['status'], msg.get('name'))
                elif msg['type'] == 'drive_removed':
                    self.remove_drive_ui(msg['drive'])
                elif msg['type'] == 'increment_counter':
                    self.increment_ui_counter(msg['counter'], msg['amount'])
                elif msg['type'] == 'request_cert':
                    self.show_cert_dialog(msg['drive'], msg.get('device_info'))

        finally:
            self.after(100, self.process_gui_queue)

    def update_drive_ui(self, drive_letter, status, name=None):
        if drive_letter not in self.drive_widgets:
            drive_frame = ctk.CTkFrame(self.drive_list_frame, fg_color="transparent")
            drive_frame.pack(fill="x", pady=5)

            drive_label = ctk.CTkLabel(drive_frame, text=f"{drive_letter}:", font=("Segoe UI Bold", 14), width=30,
                                       anchor="w")
            drive_label.pack(side="left", padx=(0, 10))

            name_label = ctk.CTkLabel(drive_frame, text=name or "Reading...", font=self.font, text_color="#D0D0D0",
                                      anchor="w")
            name_label.pack(side="left", fill="x", expand=True)

            status_label = ctk.CTkLabel(drive_frame, text="", font=("Segoe UI Semibold", 12), width=90,
                                        corner_radius=10)
            status_label.pack(side="right")

            self.drive_widgets[drive_letter] = {
                'frame': drive_frame,
                'name_label': name_label,
                'status_label': status_label
            }

        if name:
            self.drive_widgets[drive_letter]['name_label'].configure(text=name)

        status_label = self.drive_widgets[drive_letter]['status_label']
        status_map = {
            'scanning': {"text": "Scanning...", "fg": "#3498DB", "text_color": "white"},
            'infected': {"text": "Infected", "fg": "#E74C3C", "text_color": "white"},
            'certified': {"text": "Certified", "fg": "#2ECC71", "text_color": "white"},
            'clean_pending_cert': {"text": "Clean", "fg": "#F1C40F", "text_color": "black"},
        }

        config = status_map.get(status, {"text": status.capitalize(), "fg": "gray", "text_color": "white"})
        status_label.configure(text=config['text'], fg_color=config['fg'], text_color=config['text_color'])

    def remove_drive_ui(self, drive_letter):
        if drive_letter in self.drive_widgets:
            self.drive_widgets[drive_letter]['frame'].destroy()
            del self.drive_widgets[drive_letter]

    def increment_ui_counter(self, counter_name, amount):
        card_map = {
            'connected': self.connected_card,
            'certified': self.certified_card,
            'ejected': self.ejected_card
        }
        card = card_map.get(counter_name)
        if card:
            current_value = int(card.value_label.cget("text"))
            card.value_label.configure(text=str(current_value + amount))

    def show_cert_dialog(self, drive_letter, device_info=None):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Generate Certificate")

        dialog_width = 300
        dialog_height = 160

        main_window_x = self.winfo_x()
        main_window_y = self.winfo_y()
        main_window_width = self.winfo_width()
        main_window_height = self.winfo_height()

        center_x = int(main_window_x + (main_window_width - dialog_width) / 2)
        center_y = int(main_window_y + (main_window_height - dialog_height) / 2)

        dialog.geometry(f"{dialog_width}x{dialog_height}+{center_x}+{center_y}")

        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.configure(fg_color="#2B2B2B")

        label = ctk.CTkLabel(dialog, text="Validity (in days):", font=self.font)
        label.pack(pady=(20, 5))

        entry = ctk.CTkEntry(dialog, font=self.font)
        entry.insert(0, "30")
        entry.pack(pady=5, padx=20, fill="x")

        def on_generate():
            try:
                days = int(entry.get())
                if days > 0:
                    self.add_log_message(f"Generating certificate for {drive_letter}: with {days}-day validity...")
                    threading.Thread(
                        target=self.run_cert_generation,
                        args=(drive_letter, days, device_info),
                        daemon=True
                    ).start()
                    dialog.destroy()
                else:
                    print("Days must be a positive number")
            except ValueError:
                print("Invalid number for days")

        generate_btn = ctk.CTkButton(dialog, text="Generate", font=self.font, command=on_generate)
        generate_btn.pack(pady=(10, 20))

    def run_cert_generation(self, drive_letter, days, device_info=None):
        """
        Runs the actual backend certificate generation and updates the GUI when done.
        """
        try:
            # Extract optional vid/pid/serial if available
            vid = device_info.get('vid') if device_info else None
            pid = device_info.get('pid') if device_info else None
            serial = device_info.get('serial') if device_info else None

            # This now calls the real, refactored function from cert_util.py
            backend_gen_cert(drive_letter, days, vid=vid, pid=pid, serial=serial)
            self.gui_queue.put({'type': 'log', 'message': f"Certificate for {drive_letter}: successfully created."})

            # Update GUI upon completion
            self.gui_queue.put({
                'type': 'status_update',
                'drive': drive_letter,
                'status': 'certified'
            })
            self.gui_queue.put({
                'type': 'increment_counter',
                'counter': 'certified',
                'amount': 1
            })

        except Exception as e:
            self.gui_queue.put({'type': 'log', 'message': f"ERROR generating cert for {drive_letter}: {e}"})
            # Revert status if it failed
            self.gui_queue.put({
                'type': 'status_update',
                'drive': drive_letter,
                'status': 'clean_pending_cert'
            })

    def on_closing(self):
        """Handle window closing."""
        print("Closing application...")
        if self.backend_thread:
            self.backend_thread.stop()
        self.destroy()


if __name__ == "__main__":
    try:
        isAdmin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        isAdmin = False

    if not isAdmin:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        app = App()
        app.protocol("WM_DELETE_WINDOW", app.on_closing)
        app.mainloop()
