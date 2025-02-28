# D-revSHELL-ARP

**D-revSHELL-ARP** is a powerful and interactive Man-in-the-Middle (MITM) attack tool designed for penetration testing and ethical hacking purposes. It combines ARP spoofing, DNS spoofing, and reverse shell injection to demonstrate the vulnerabilities in network security. This tool is intended for educational and authorized testing only.

---

## Features

- **ARP Spoofing**: Redirects traffic between the target and the gateway.
- **DNS Spoofing**: Spoofs DNS requests to redirect traffic to a malicious server.
- **Reverse Shell Injection**: Injects a reverse shell payload into the target's browser.
- **Interactive Menu**: Easy-to-use interactive menu for configuring and running attacks.
- **Logging**: Logs all attack details for later analysis.
- **Restoration**: Automatically restores network settings after the attack.
- **Colorful Output**: Beautifully formatted and colored terminal output.
- **ASCII Art**: Eye-catching ASCII art for a professional look.

---

## Prerequisites

- **Kali Linux** (or any Linux distribution with root access)
- **Python 3.x**
- **dsniff** (for `arpspoof` and `dnsspoof`)
- **Netcat** (for reverse shell listener)

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/D-revSHELL-ARP.git
   cd D-revSHELL-ARP
Install dependencies:

bash
Copy
sudo apt update
sudo apt install dsniff netcat
Make the script executable:

bash
Copy
chmod +x drevshell_arp.py
Usage
Run the script with root privileges:

bash
Copy
sudo ./drevshell_arp.py
Follow the interactive menu:

Start Attack: Configure and launch the MITM attack.

Restore Settings: Restore network settings after the attack.

Exit: Exit the script.

Example Workflow:

Enter the target IP, gateway IP, and redirect IP.

Optionally, inject a reverse shell by providing the listener IP and port.

Start the attack and monitor the results.

Start a reverse shell listener (if reverse shell injection is used):

bash
Copy
nc -lvnp <listener_port>
Example
Step 1: Start the Attack
bash
Copy
sudo ./drevshell_arp.py
Step 2: Configure the Attack
Target IP: 192.168.1.100

Gateway IP: 192.168.1.1

Redirect IP: 192.168.1.200

Domains to spoof: example.com,test.com

Inject reverse shell: y

Listener IP: 192.168.1.200

Listener Port: 4444

Step 3: Start the Listener
bash
Copy
nc -lvnp 4444
Step 4: Monitor the Attack
The script will display real-time status updates.

If a reverse shell is injected, the target's browser will connect to your listener.

Step 5: Restore Settings
Use the Restore Settings option to clean up and restore the network.

Warning
Legal Use Only: This tool is intended for educational and authorized penetration testing only. Unauthorized use is illegal and unethical.

Use Responsibly: Always obtain proper permissions before using this tool on any network.

Contributing
Contributions are welcome! If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgments
Inspired by various open-source penetration testing tools.

Special thanks to the cybersecurity community for their contributions.

Author
Your Name
GitHub: your-username
Email: your-email@example.com
