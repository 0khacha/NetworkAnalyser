Wi-Fi Network Analyzer
Wi-Fi Network Analyzer is a tool designed to scan for nearby Wi-Fi networks, provide detailed information about them, and run speed tests. The application features a graphical user interface (GUI) built with Tkinter, and uses pywifi for network scanning and speedtest-cli for speed tests.

Features
Network Scanning: Scan for nearby Wi-Fi networks and display detailed information including BSSID, SSID, signal strength, authentication type, encryption type, channel, and WPS status.
Speed Testing: Run download and upload speed tests on the selected network.
Data Visualization: Plot real-time signal strength over time.
Auto-Refresh: Automatically refresh the network list at specified intervals.
Export to CSV: Export the network details to a CSV file.
Theme and Styling: Toggle between dark mode and light mode themes.
Help and Documentation: Built-in help and about sections.
Prerequisites
Python 3.6 or higher
The following Python packages:
tkinter
pywifi
speedtest-cli
matplotlib
Installation
Clone the Repository:

bash
Copy code
git clone https://github.com/0khacha/NetworkAnalyser.git
cd networksproject
Install Required Packages:

bash
Copy code
pip install pywifi speedtest-cli matplotlib
Run the Application:

bash
Copy code
python wifi_analyzer.py
Usage
Scan for Networks:

Click the "Scan for Networks" button to start scanning for nearby Wi-Fi networks.
The network list will be populated with the details of the discovered networks.
Run Speed Test:

Select a network from the list.
Click the "Run Speed Test" button to perform a speed test on the selected network.
View Network Details:

Select a network from the list to view detailed information about it in the panel below.
Plot Signal Strength:

The signal strength of the selected network will be plotted over time in the graph.
Auto-Refresh:

Click the "Auto-Refresh" button to enable automatic refreshing of the network list every minute.
Export to CSV:

Click the "Export to CSV" button to save the network details to a CSV file.
Toggle Theme:

Use the "View" menu to toggle between dark mode and light mode.
Menu Options
File:

Export to CSV: Save the network details to a CSV file.
Exit: Exit the application.
View:

Toggle Dark Mode: Switch between dark mode and light mode.
Help:

Help: Show help information about the application.
About: Show information about the application and its developer.
Troubleshooting
No Wi-Fi Interface Found:

Ensure that your device has a Wi-Fi adapter and that it is enabled.
Verify that the necessary permissions are granted to access the Wi-Fi interface.
Error During Network Scan or Speed Test:

Check the log files in the logs directory for detailed error messages.
Ensure that you have a stable internet connection.
License
This project is licensed under the MIT License. See the LICENSE file for more details.

Contributing
Contributions are welcome! Please open an issue or submit a pull request on GitHub.

Acknowledgments
This application uses the pywifi library for Wi-Fi network scanning.
Speed tests are performed using the speedtest-cli library.
GUI components are built with tkinter.
Contact
For any questions or issues, please contact [mohamedkhacha99@gmail.com].
