import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import pywifi
from pywifi import const
import time
import json
import operator
import pixiedust

@pixiedust.capture(output="display")
def retrieve_wps_pin(ssid):
    """Retrieve WPS pin without using PixieDust."""
    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        profile = iface.profile()
        for wifiProfile in iface.profiles():
            if wifiProfile.ssid == ssid:
                profile = wifiProfile
                break
        pin = profile.wps_pin
        messagebox.showinfo("WPS Pin", f"The WPS Pin for {ssid} is: {pin}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def scan_networks():
    """Scan for available Wi-Fi networks."""
    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]  # Assuming the first interface is the Wi-Fi interface
        iface.scan()
        time.sleep(5)  # Wait for the scan to complete
        scan_results = iface.scan_results()
        networks = []
        for network in scan_results:
            ssid = network.ssid if network.ssid else "<Hidden Network>"
            if ssid == "<Hidden Network>":
                ssid = get_ssid_for_hidden_network(network.bssid)
            auth_type = get_auth_type(network.akm)
            encryption_type = get_encryption_type(network.cipher)
            potential_attack = check_potential_attack(auth_type, encryption_type, network)
            wps_locked = get_wps_lock_status(network)
            channel = calculate_channel(network.freq)
            network_info = {
                'ssid': ssid,
                'bssid': network.bssid,
                'signal': network.signal,
                'auth': auth_type,
                'encryption': encryption_type,
                'frequency': network.freq,
                'channel': channel,  # Calculate channel from frequency
                'potential_attack': potential_attack,
                'wps_locked': wps_locked
            }
            networks.append(network_info)
        return networks
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return []

def get_ssid_for_hidden_network(bssid):
    """Retrieve the SSID for a hidden network based on its BSSID."""
    history = load_hidden_networks()
    for entry in history:
        if entry['bssid'] == bssid:
            return entry['ssid']
    # If not found, prompt the user for the SSID and save it
    ssid = simpledialog.askstring("Hidden Network Detected", f"Enter SSID for hidden network with BSSID {bssid}:")
    if ssid:
        save_hidden_network_ssid(bssid, ssid)
    return ssid if ssid else "<Unknown SSID>"

def calculate_channel(frequency):
    """Calculate the Wi-Fi channel from the frequency."""
    if frequency == 2484:
        return 14
    elif frequency < 2484:
        return int((frequency - 2412) / 5) + 1
    else:
        return int((frequency - 5000) / 5) + 34

def get_auth_type(akm):
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

    for auth in akm:
        akm_str.append(akm_types.get(auth, "Unknown"))

    return "/".join(akm_str)

def get_encryption_type(cipher):
    """Return a human-readable encryption type."""
    if not cipher:
        return "None"
    encryption_types = []
    cipher_types = {
        const.CIPHER_TYPE_NONE: "None",
        const.CIPHER_TYPE_WEP: "WEP",
        const.CIPHER_TYPE_TKIP: "TKIP",
        const.CIPHER_TYPE_CCMP: "AES",
    }
    if hasattr(const, 'CIPHER_TYPE_GCMP256'):
        cipher_types[const.CIPHER_TYPE_GCMP256] = "GCMP-256"

    encryption_types.append(cipher_types.get(cipher, "Unknown"))

    return "/".join(encryption_types)

def check_potential_attack(auth_type, encryption_type, network):
    """Check for potential attacks based on the authentication and encryption type."""
    if "WEP" in auth_type or "WEP" in encryption_type:
        return "Potential WEP Attack"
    elif "WPA" in auth_type and "TKIP" in encryption_type:
        return "Potential TKIP Attack"
    elif "Open" in auth_type:
        return "Potential Open Network Attack"
    elif "None" in encryption_type:
        return "Potential Open Network Attack"
    elif network.ssid.lower().startswith("free") or network.ssid.lower().startswith("public"):
        return "Potential Rogue AP Attack"
    elif len(network.bssid.split(':')) != 6:
        return "Potential MAC Spoofing Attack"
    else:
        return "No known potential attack"

def get_wps_lock_status(network):
    """Return the WPS lock status."""
    # Placeholder implementation, replace with actual check if available
    return False

def update_network_info(event):
    """Update the displayed information based on the selected network."""
    selected_item = tree.selection()
    if selected_item:
        selected_network = tree.item(selected_item)['values'][0]
        for network in available_networks:
            if network['bssid'] == selected_network:
                network_info.set(f"SSID: {network['ssid']}\n"
                                 f"BSSID: {network['bssid']}\n"
                                 f"Signal: {network['signal']} dBm\n"
                                 f"Auth: {network['auth']}\n"
                                 f"Encryption: {network['encryption']}\n"
                                 f"Frequency: {network['frequency']} MHz\n"
                                 f"Channel: {network['channel']}\n"
                                 f"Potential Attack: {network['potential_attack']}\n"
                                 f"WPS Locked: {network['wps_locked']}")
                break

def connect_to_network():
    """Handle the Connect button click event."""
    selected_item = tree.selection()
    if selected_item:
        selected_network = tree.item(selected_item)['values'][0]
        for network in available_networks:
            if network['bssid'] == selected_network:
                auth_type = network['auth']
                if auth_type == "Open":
                    connect_to_network(selected_network, auth_type)
                else:
                    password = simpledialog.askstring(
                    "Password", "Enter the network password:", show="*")
                    if password:
                        connect_to_network(network['ssid'], auth_type, password)
                break

def refresh_networks():
    """Refresh the list of available networks."""
    global available_networks
    available_networks = scan_networks()
    for row in tree.get_children():
        tree.delete(row)
    for network in available_networks:
        tree.insert('', 'end', values=(
            network['bssid'], network['channel'], network['signal'], network['wps_locked'], network['ssid']
        ))

def sort_networks(sort_key, reverse=False):
    """Sort the available networks based on the given key."""
    global available_networks
    available_networks.sort(key=operator.itemgetter(sort_key), reverse=reverse)
    refresh_networks()

def filter_networks(filter_key, filter_value):
    """Filter the available networks based on the given key and value."""
    filtered_networks = [network for network in available_networks if str(network[filter_key]).startswith(filter_value)]
    for row in tree.get_children():
        tree.delete(row)
    for network in filtered_networks:
        tree.insert('', 'end', values=(
            network['bssid'], network['channel'], network['signal'], network['wps_locked'], network['ssid']
        ))

def save_network_history(ssid, auth, password=None):
    """Save the network information to the history file."""
    network_info = {
        'ssid': ssid,
        'auth': auth,
        'password': password
    }
    try:
        with open('network_history.json', 'r') as f:
            history = json.load(f)
    except FileNotFoundError:
        history = []

    history.append(network_info)

    with open('network_history.json', 'w') as f:
        json.dump(history, f, indent=4)

def save_hidden_network_ssid(bssid, ssid):
    """Save the SSID for a hidden network based on its BSSID."""
    hidden_network_info = {
        'bssid': bssid,
        'ssid': ssid
    }
    try:
        with open('hidden_networks.json', 'r') as f:
            hidden_networks = json.load(f)
    except FileNotFoundError:
        hidden_networks = []

    hidden_networks.append(hidden_network_info)

    with open('hidden_networks.json', 'w') as f:
        json.dump(hidden_networks, f, indent=4)

def load_hidden_networks():
    """Load the hidden networks from the file."""
    try:
        with open('hidden_networks.json', 'r') as f:
            hidden_networks = json.load(f)
        return hidden_networks
    except FileNotFoundError:
        return []

def disconnect_from_network():
    """Disconnect from the currently connected network."""
    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        iface.disconnect()
        messagebox.showinfo("Disconnected", "Successfully disconnected from the network.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Create the main window
root = tk.Tk()
root.title("Wi-Fi Network Information")

# Scan for networks
available_networks = scan_networks()

# Create the Treeview widget
columns = ("BSSID", "Channel", "RSSI", "WPS Locked", "ESSID")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
tree.pack(padx=10, pady=10, fill="both", expand=True)
tree.bind("<<TreeviewSelect>>", update_network_info)

# Populate the Treeview with the scanned networks
for network in available_networks:
    tree.insert('', 'end', values=(
        network['bssid'], network['channel'], network['signal'], network['wps_locked'], network['ssid']
    ))

# Display network information
network_info = tk.StringVar()
info_label = ttk.Label(root, textvariable=network_info, justify="left")
info_label.pack(padx=10, pady=10)

# Create the Connect button
connect_button = ttk.Button(root, text="Connect", command=connect_to_network)
connect_button.pack(padx=10, pady=10)

# Create the Refresh button
refresh_button = ttk.Button(root, text="Refresh", command=refresh_networks)
refresh_button.pack(padx=10, pady=10)

# Create the Disconnect button
disconnect_button = ttk.Button(root, text="Disconnect", command=disconnect_from_network)
disconnect_button.pack(padx=10, pady=10)

# Start the main event loop
root.mainloop()
