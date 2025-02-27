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
