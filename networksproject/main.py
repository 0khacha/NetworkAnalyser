import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import pywifi
from pywifi import const
import time
import logging
from threading import Thread, Lock
import os
import speedtest as st
import csv
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime


class WifiAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Wi-Fi Network Analyzer")
        self.geometry("1000x700")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.create_widgets()
        self.networks = []
        self.scanning = False
        self.speed_testing = False
        self.lock = Lock()
        self.configure_logging()

    def configure_logging(self):
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "wifi_analyzer.log")
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
        )

    def create_widgets(self):
        style = ttk.Style()
        style.configure("Treeview.Heading", font=("Helvetica", 10, "bold"))
        style.configure("Treeview", font=("Helvetica", 10))

        self.tree = ttk.Treeview(
            self,
            columns=(
                "BSSID",
                "SSID",
                "Signal",
                "Auth",
                "Encryption",
                "Channel",
                "WPS Enabled",
                "Download Speed",
                "Upload Speed"
            ),
            show="headings",
        )
        self.tree.heading("BSSID", text="BSSID")
        self.tree.heading("SSID", text="SSID")
        self.tree.heading("Signal", text="Signal (dBm)")
        self.tree.heading("Auth", text="Auth")
        self.tree.heading("Encryption", text="Encryption")
        self.tree.heading("Channel", text="Channel")
        self.tree.heading("WPS Enabled", text="WPS Enabled")
        self.tree.heading("Download Speed", text="Download Speed (Mbps)")
        self.tree.heading("Upload Speed", text="Upload Speed (Mbps)")
        self.tree.pack(fill=tk.BOTH, expand=True)

        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        scan_button = tk.Button(button_frame, text="Scan for Networks", command=self.scan_networks)
        scan_button.pack(side=tk.LEFT, padx=5)

        speed_test_button = tk.Button(button_frame, text="Run Speed Test", command=self.run_speed_test)
        speed_test_button.pack(side=tk.LEFT, padx=5)

        refresh_button = tk.Button(button_frame, text="Refresh", command=self.update_network_list)
        refresh_button.pack(side=tk.LEFT, padx=5)

        export_button = tk.Button(button_frame, text="Export to CSV", command=self.export_to_csv)
        export_button.pack(side=tk.LEFT, padx=5)

        auto_refresh_button = tk.Button(button_frame, text="Auto-Refresh", command=self.auto_refresh)
        auto_refresh_button.pack(side=tk.LEFT, padx=5)

        self.network_info = tk.StringVar()
        network_info_label = tk.Label(self, textvariable=self.network_info, justify=tk.LEFT, anchor=tk.NW)
        network_info_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.tree.bind("<<TreeviewSelect>>", self.update_network_info)

        self.figure, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.figure, master=self)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.signal_strength_data = []

    def on_closing(self):
        self.destroy()

    def get_wifi_interface(self):
        wifi = pywifi.PyWiFi()
        ifaces = wifi.interfaces()
        if not ifaces:
            messagebox.showerror("Error", "No Wi-Fi interface found")
            return None
        return ifaces[0]

    def scan_networks(self):
        if self.scanning:
            logging.info("Network scan is already in progress.")
            return

        self.scanning = True
        scan_thread = Thread(target=self.perform_network_scan)
        scan_thread.start()

    def perform_network_scan(self):
        try:
            iface = self.get_wifi_interface()
            if not iface:
                logging.error("No Wi-Fi interface found")
                self.scanning = False
                return

            self.network_info.set("Scanning for networks...")
            iface.scan()
            time.sleep(5)  # Wait for the scan to complete
            scan_results = iface.scan_results()
            self.networks = []
            for network in scan_results:
                ssid = network.ssid or "<Hidden Network>"
                auth_type = self.get_auth_type(network.akm)
                encryption_type = self.get_encryption_type(network.cipher)
                channel = self.calculate_channel(network.freq)

                wps_enabled = "No"
                if hasattr(network, 'wps'):
                    wps_enabled = "Yes" if network.wps else "No"

                network_info = {
                    'ssid': ssid,
                    'bssid': network.bssid,
                    'signal': network.signal,
                    'auth': auth_type,
                    'encryption': encryption_type,
                    'frequency': network.freq,
                    'channel': channel,
                    'wps_enabled': wps_enabled,
                    'download_speed': 'N/A',
                    'upload_speed': 'N/A'
                }
                self.networks.append(network_info)

            self.update_network_list()
            logging.info(f"Found {len(self.networks)} networks")
        except Exception as e:
            logging.error(f"Error during network scan: {str(e)}")
            messagebox.showerror("Error", f"Error during network scan: {str(e)}")
        finally:
            self.scanning = False
            self.network_info.set("")

    def update_network_list(self):
        with self.lock:
            self.tree.delete(*self.tree.get_children())
            for network in self.networks:
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        network['bssid'],
                        network['ssid'],
                        network['signal'],
                        network['auth'],
                        network['encryption'],
                        network['channel'],
                        network['wps_enabled'],
                        network['download_speed'],
                        network['upload_speed']
                    ),
                )

    def update_network_info(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            selected_network = self.tree.item(selected_item)['values']
            network_info_text = (
                f"SSID: {selected_network[1]}\n"
                f"BSSID: {selected_network[0]}\n"
                f"Signal: {selected_network[2]} dBm\n"
                f"Auth: {selected_network[3]}\n"
                f"Encryption: {selected_network[4]}\n"
                f"Channel: {selected_network[5]}\n"
                f"WPS Enabled: {selected_network[6]}\n"
                f"Download Speed: {selected_network[7]} Mbps\n"
                f"Upload Speed: {selected_network[8]} Mbps"
            )
            self.network_info.set(network_info_text)
            self.plot_signal_strength(selected_network[1], selected_network[2])

    def run_speed_test(self):
        if self.speed_testing:
            logging.info("Speed test is already in progress.")
            return

        self.speed_testing = True
        speed_test_thread = Thread(target=self.perform_speed_test)
        speed_test_thread.start()

    def perform_speed_test(self):
        try:
            logging.info("Starting speed test for the connected network")
            self.network_info.set("Performing speed test...")
            speedtest = st.Speedtest()
            speedtest.get_best_server()
            download_speed = speedtest.download() / 1_000_000  # Convert to Mbps
            upload_speed = speedtest.upload() / 1_000_000  # Convert to Mbps

            iface = self.get_wifi_interface()
            if iface is None:
                logging.error("No Wi-Fi interface found for speed test")
                return

            status = iface.status()
            connected_network = None
            if status == const.IFACE_CONNECTED:
                connected_ssid = iface.network_profiles()[0].ssid
                for net in self.networks:
                    if net['ssid'] == connected_ssid:
                        net['download_speed'] = round(download_speed, 2)
                        net['upload_speed'] = round(upload_speed, 2)
                        connected_network = net
                        break

            self.update_network_list()
            if connected_network:
                logging.info(f"Speed test completed for SSID: {connected_network['ssid']} - Download: {download_speed:.2f} Mbps, Upload: {upload_speed:.2f} Mbps")
            else:
                logging.error("Connected network not found in the scanned list.")
        except Exception as e:
            logging.error(f"Error during speed test: {str(e)}")
            messagebox.showerror("Error", f"Error during speed test: {str(e)}")
        finally:
            self.speed_testing = False
            self.network_info.set("")

    def calculate_channel(self, frequency):
        """Calculate the Wi-Fi channel from the frequency."""
        if frequency in [2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472, 2484]:
            channel = (frequency - 2412) // 5 + 1
        elif frequency in [5000, 5010, 5020, 5030, 5040, 5050, 5060, 5070, 5080, 5170, 5180, 5190, 5200, 5210, 5220, 5230, 5240, 5260, 5280, 5300, 5320, 5500, 5510, 5520, 5530, 5540, 5550, 5560, 5570, 5580, 5590, 5600, 5610, 5620, 5630, 5640, 5650, 5660, 5670, 5680, 5690, 5700, 5710, 5720, 5745, 5765, 5785, 5805, 5825, 5845]:
            channel = (frequency - 5000) // 5 + 34
        else:
            channel = "Unknown"
        return channel

    def get_auth_type(self, akm):
        """Return a human-readable authentication type."""
        if not akm:
            return "Open"
        akm_str = []
        akm_types = {
            const.AKM_TYPE_NONE: "None",
            const.AKM_TYPE_WPA: "WPA",
            const.AKM_TYPE_WPAPSK: "WPA-PSK",
            const.AKM_TYPE_WPA2: "WPA2",
            const.AKM_TYPE_WPA2PSK: "WPA2-PSK",
        }
        if hasattr(const, 'AKM_TYPE_WPA3'):
            akm_types[const.AKM_TYPE_WPA3] = "WPA3"
        if hasattr(const, 'AKM_TYPE_WPA3SAE'):
            akm_types[const.AKM_TYPE_WPA3SAE] = "WPA3-SAE"

        for a in akm:
            akm_str.append(akm_types.get(a, "Unknown"))

        return "/".join(akm_str)

    def get_encryption_type(self, cipher):
        """Return a human-readable encryption type."""
        if not cipher:
            return "None"
        encryption_types = []
        cipher_types = {
            const.CIPHER_TYPE_NONE: "None",
            const.CIPHER_TYPE_WEP: "WEP",
            const.CIPHER_TYPE_TKIP: "TKIP",
            const.CIPHER_TYPE_CCMP: "AES",
            const.CIPHER_TYPE_GCMP: "GCMP",
            const.CIPHER_TYPE_GCMP256: "GCMP-256",
        }

        for c in cipher:
            encryption_types.append(cipher_types.get(c, "Unknown"))

        return "/".join(encryption_types)

    def plot_signal_strength(self, ssid, signal_strength):
        current_time = datetime.now().strftime("%H:%M:%S")
        self.signal_strength_data.append((current_time, signal_strength))

        times, signals = zip(*self.signal_strength_data)

        self.ax.clear()
        self.ax.plot(times, signals, label=ssid)
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Signal Strength (dBm)')
        self.ax.set_title('Signal Strength Over Time')
        self.ax.legend()
        self.figure.autofmt_xdate()
        self.canvas.draw()

    def export_to_csv(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if filename:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ["BSSID", "SSID", "Signal", "Auth", "Encryption", "Channel", "WPS Enabled", "Download Speed", "Upload Speed"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for network in self.networks:
                    writer.writerow(network)
            logging.info(f"Exported network details to {filename}")

    def auto_refresh(self):
        self.after(60000, self.scan_networks)


if __name__ == "__main__":
    app = WifiAnalyzer()
    app.mainloop()
