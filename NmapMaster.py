#Nmap Master
#Made by MusicalVR


#!/usr/bin/python3
import nmap
import subprocess
import requests
import socket

def initial_scan(network_range, scan_type):
    nm = nmap.PortScanner()
    scan_arguments = {
        "insane": "-sS -T5 -A",
        "stealth": "-sS -T2",
        "normal": "-sS -T3 -A",
        "quick": "-sS -T4 -F",
    }

    print(f"Starting initial scan on {network_range} with scan type '{scan_type}'...")
    scan_arg = scan_arguments.get(scan_type.lower(), "-sS -T3 -A")
    nm.scan(hosts=network_range, arguments=scan_arg)

    live_hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f"Host {host} is up")
            live_hosts.append(host)

    return live_hosts

def identify_switch_firewall_printer_server_router(host, ports, os_matches):
    switch_ports = {161, 162}
    firewall_ports = {500, 4500}
    printer_ports = {9100, 515, 631}
    server_ports = {21, 22, 80, 443, 3389, 3306}
    router_ports = {23, 80, 443, 500, 179}

    is_switch = any(port in ports for port in switch_ports)
    is_firewall = any(port in ports for port in firewall_ports)
    is_printer = any(port in ports for port in printer_ports)
    is_server = any(port in ports for port in server_ports)
    is_router = any(port in ports for port in router_ports)

    if os_matches:
        for match in os_matches:
            os_name = match['name'].lower()
            if 'cisco' in os_name or 'juniper' in os_name or 'firewall' in os_name:
                is_switch = is_switch or 'switch' in os_name
                is_firewall = is_firewall or 'firewall' in os_name
            if 'printer' in os_name or 'jetdirect' in os_name:
                is_printer = True
            if 'windows server' in os_name or 'linux' in os_name or 'unix' in os_name:
                is_server = True
            if 'router' in os_name or 'gateway' in os_name or 'openwrt' in os_name or 'mikrotik' in os_name:
                is_router = True

    return is_switch, is_firewall, is_printer, is_server, is_router

def run_follow_up_scripts(host, ports, os_matches=None):
    print("Running follow-up scripts on {}...".format(host))

    try:
        is_switch, is_firewall, is_printer, is_server, is_router = identify_switch_firewall_printer_server_router(host, ports, os_matches)

        if is_switch:
            print(f"Switch detected on {host}. Running switch-specific scripts...")
            subprocess.run(["nmap", "-p 161", "--script=snmp-info", host], timeout=60)

        if is_firewall:
            print(f"Firewall detected on {host}. Running firewall-specific scripts...")
            subprocess.run(["nmap", "--script=firewall-bypass", host], timeout=60)

        if is_printer:
            print(f"Printer detected on {host}. Running printer-specific scripts...")
            subprocess.run(["nmap", "-p 9100,515,631", "--script=printer-info", host], timeout=60)

        if is_server:
            print(f"Server detected on {host}. Running server-specific scripts...")
            if 21 in ports:
                subprocess.run(["nmap", "-p 21", "--script=ftp-anon", host], timeout=60)
            if 3306 in ports:
                subprocess.run(["nmap", "-p 3306", "--script=mysql-info", host], timeout=60)

        if is_router:
            print(f"Router/Gateway detected on {host}. Running router-specific scripts...")
            if 23 in ports:
                subprocess.run(["nmap", "-p 23", "--script=telnet-encryption", host], timeout=60)
            if 500 in ports:
                subprocess.run(["nmap", "-p 500", "--script=ike-version", host], timeout=60)
            if 80 in ports or 443 in ports:
                subprocess.run(["nmap", "-p 80,443", "--script=http-vuln-cve2017-5638", host], timeout=60)

        if not (is_switch or is_firewall or is_printer or is_server or is_router):
            print(f"Unknown device on {host}. Running basic vulnerability scans...")
            subprocess.run(["nmap", "-sV", "--script=vuln", host], timeout=120)

    except subprocess.TimeoutExpired:
        print(f"Subprocess execution timed out for host {host}.")

def detailed_recon_scan(host):
    print(f"Starting reconnaissance scan on {host}...")

    command = ["nmap", "-p", "1-1024", "-sV", "-O", "--script=banner", host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)

        open_ports = {}
        os_matches = []

        if result.returncode == 0:
            output = result.stdout
            print(output)

            # Parse open ports from output
            for line in output.splitlines():
                if "/tcp" in line and "open" in line:
                    port = int(line.split("/")[0])
                    service = line.split()[2]
                    open_ports[port] = service

            # Extract OS matches if available
            if "OS details:" in output:
                os_info = output.split("OS details:")[1].strip().splitlines()[0]
                os_matches.append({"name": os_info})

        return open_ports, os_matches

    except subprocess.TimeoutExpired:
        print(f"Scanning of {host} timed out.")
        return {}, []

def probe_web_server(host, port):
    try:
        url = f"http://{host}:{port}" if port in [80, 8080, 8000] else f"https://{host}:{port}"
        print(f"Probing web server at {url}...")
        response = requests.get(url, timeout=5)
        print(f"Response from {url}: {response.status_code} {response.reason}")
    except requests.exceptions.RequestException as e:
        print(f"Error probing {url}: {e}")

def dns_recon(host):
    try:
        print(f"Performing DNS reconnaissance on {host}...")
        try:
            hostname, aliases, _ = socket.gethostbyaddr(host)
            print(f"Reverse DNS lookup result for {host}: {hostname} (Aliases: {', '.join(aliases)})")
        except socket.herror:
            print(f"Reverse DNS lookup failed for {host}")

        try:
            ip_addresses = socket.gethostbyname_ex(host)
            print(f"DNS lookup for {host} resolved to: {ip_addresses[2]}")
        except socket.gaierror:
            print(f"DNS lookup failed for {host}")

    except Exception as e:
        print(f"Error performing DNS reconnaissance on {host}: {e}")

def vulnerability_scan(host):
    print(f"Running vulnerability scan on {host}...")
    subprocess.run(["nmap", "-sV", "--script=vuln", host])

def main():
    network_range = input("Please enter the network range to scan (e.g., '192.168.1.0/24'): ")
    scan_type = input("Please enter the scan type (insane, stealth, normal, quick): ")

    live_hosts = initial_scan(network_range, scan_type)

    for host in live_hosts:
        open_ports, os_matches = detailed_recon_scan(host)
        if open_ports:
            run_follow_up_scripts(host, open_ports, os_matches)
            dns_recon(host)
            vulnerability_scan(host)

if __name__ == "__main__":
    main()

