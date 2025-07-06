import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import random
from re import sub
import nmap3
import netifaces
import os
from pathlib import Path
import prettytable
import requests
from scapy.all import ARP, Ether, ICMP, IP, srp, sr1, RandShort
from scapy.config import Conf
import socket
import shlex
import subprocess
import threading
import time
from tqdm import tqdm
from typing import List, Optional
import webbrowser
import xml.etree.ElementTree as ET

### Custom imports for classes
from src.classes import Device, Interface, Network, Port, Vulnerability, CPE

### Custom imports for web application
from src.app.API.app import create_app

Conf.verb = 0

FORMATS = ["table", "json", "web"]

def nmap_vulners_script(nmap: nmap3.Nmap, target, vulners_script="--script vulners", args="-sV", timeout=None)->List[Vulnerability]:
    """
    Perform an Nmap scan using the vulners script.

    :param target: Target IP or domain.
    :param vulners_script: The vulners script to use.
    :param args: Additional arguments for the Nmap command.
    :param timeout: Timeout for the scan.
    :return: Dictionary containing vulnerability information.
    """
    try:
        nmap.target = target
        vulners_args = "{target} {default}".format(target=target, default=vulners_script)

        if args:
            vulners_args += " {0}".format(args)

        vulners_command = nmap.default_command() + " " + vulners_args
        vulners_shlex = shlex.split(vulners_command)

        # Run the command and get the output
        output = nmap.run_command(vulners_shlex, timeout=timeout)
        
        if not output:
            print(f"No output from nmap for {target}")
            return []

        # Parse the XML output
        xml_root = ET.fromstring(output)

        # Extract vulnerability information
        vulnerabilities = []

        # Iterate over each host
        for host in xml_root.findall('host'):
            # Iterate over each port
            for port in host.findall('ports/port'):
                # Find the script element with id 'vulners'
                vulners_script = port.find("script[@id='vulners']")
                if vulners_script:
                    
                    service = port.find('service')
                    if service is None:
                        continue
                    
                    portid = port.get('portid')
                    protocol = port.get('protocol')
                    if portid is None or protocol is None:
                        continue
                        
                    vuln = {
                        'port': Port(number=int(portid), protocol=protocol),
                        'service': service.get('name', 'unknown'),
                        'product': service.get('product', 'unknown'),
                        'version': service.get('version', 'unknown'),
                        'cpes': []
                    }
                    
                    cpes = vulners_script.findall("table/table")
                    for cpe in cpes:
                        try:
                            id_elem = cpe.find("elem[@key='id']")
                            cvss_elem = cpe.find("elem[@key='cvss']")
                            type_elem = cpe.find("elem[@key='type']")
                            
                            if id_elem is not None and cvss_elem is not None and type_elem is not None:
                                id_text = id_elem.text
                                cvss_text = cvss_elem.text
                                type_text = type_elem.text
                                
                                if id_text is not None and cvss_text is not None and type_text is not None:
                                    data = {
                                        'id': id_text,
                                        'cvss': cvss_text,
                                        'type': type_text,
                                    }
                                    data["ref"] = f"https://vulners.com/{data['type']}/{data['id']}"
                                    vuln['cpes'].append(CPE(**data))
                        except Exception as e:
                            print(f"Error parsing CPE for {target}: {e}")
                            continue
                    
                    try:
                        vuln = Vulnerability(**vuln)
                        vulnerabilities.append(vuln)
                    except Exception as e:
                        print(f"Error creating Vulnerability object for {target}: {e}")
                        continue

        return vulnerabilities
    except Exception as e:
        print(f"Error in nmap_vulners_script for {target}: {e}")
        return []

def get_if_name(network: ipaddress.IPv4Network)->str|None:    
    
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for addr_info in addresses[netifaces.AF_INET]:
                ip = addr_info['addr']
                if ip in [str(ip) for ip in network]:
                    print(f"Using interface {interface}")
                    return interface
    print("No interface found")
    return None

def get_gateway(interface: str)->Interface|None:

    gateways = netifaces.gateways()[netifaces.AF_INET]
    
    for gw in gateways:
        if gw[1] == interface:
            return Interface(ip = gw[0], name = gw[1])
        
    return None

def get_router(devices: List[Device], interface: Interface)->Device|None:
    for device in devices:
        if device.ip == interface.ip:
            return device

    return None

def get_targets(network: ipaddress.IPv4Network)->List[str]:
    hosts = [
        str(ip) for ip in network.hosts()
    ]

    return hosts

def traceroute(target_ip, max_hops=30):
    hops = list()
    
    for ttl in range(1, max_hops + 1):
        # Create an IP packet with increasing TTL
        packet = IP(dst=str(target_ip), ttl=ttl) / ICMP(id=RandShort(), seq=1)

        # Send the packet and wait for a reply
        reply = sr1(packet, verbose=0, timeout=2)

        if reply is None:
            # No reply received
            pass
        elif reply.type == 3 and reply.code == 0:
            # ICMP Time Exceeded message
            hops.append(reply.src)
        elif reply.src == str(target_ip):
            # Reached the target
            hops.append(reply.src)
            break
        else:
            # Other ICMP messages
            hops.append(reply.src)
            
    return hops

def arp_ping_scan(target):
    # Create an ARP request
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and get responses
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "Unknown"
        devices.append(Device(ip=ip, mac=mac, hostname=hostname))
    
    if devices == list():
        return None
    else:
        return devices[0]

def icmp_ping_scan(target):
    # Create an ICMP request
    packet = IP(dst=target)/ICMP()

    # Send the packet and wait for a reply
    reply = sr1(packet, timeout=2, verbose=0)

    if reply is not None:
        ip = reply.src
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "Unknown"
        return Device(ip=ip, hostname=hostname)
    else:
        return None
    
    
def parallel_icmp_scan(targets, function, description="Scanning"):
    
    devices = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(tqdm(executor.map(function, targets), total=len(targets), desc=description))

    for result in results:
        if result:
            devices.append(result)

    return devices

def nmap_scanner(network):
    scanner = nmap3.NmapHostDiscovery()
    results = scanner.nmap_no_portscan(network)
    res = list()
    
    devices = [
        {
            "ip": ip_addr
        }
            for ip_addr, info in results.items()
            if "state" in info and info["state"]["state"] == "up"
    ]
    
    for device in devices:
        try:
            hostname = socket.gethostbyaddr(device["ip"])[0]
        except socket.herror:
            hostname = "Unknown"
        res.append(Device(ip=device["ip"], hostname=hostname))
    
    return res

def concatenate_devices(*lists: List[Device], )->List[Device]:
    result = set()
    
    for l in lists:
        for device in l:
            result.add(device)
    
    return list(result)

def scan_vulnerabilities(device, nmap):
    """Scan vulnerabilities for a specific device
    Args:
        device (Device): Device to scan
        nmap (nmap3.Nmap): Nmap instance
    Returns:
        Device: Updated device with vulnerabilities
    """
    try:
        vulnerabilities = nmap_vulners_script(nmap=nmap, target=device.ip)
        device.set_vulnerabilities(vulnerabilities)
        if vulnerabilities:
            print(f"Found {len(vulnerabilities)} vulnerabilities on {device.ip}")
        return device
    except Exception as e:
        print(f"Error scanning vulnerabilities for {device.ip}: {e}")
        device.set_vulnerabilities([])
        return device

def format_table(devices: List[Device])->None:
    result_table = prettytable.PrettyTable(["Hostname", "IP", "MAC", "OS", "OS Family", "Hops"])
    for device in devices:
        result_table.add_row([device.hostname, device.ip, device.mac, device.os, device.os_family, device.hops])
    
    print(result_table)
    
    
def format_json(devices: List[Device], output: Optional[Path] = None)->None:
    if not output: 
        print(json.dumps([device.to_dict() for device in devices], indent=4))
    else:
        with open(output, "w") as f:
            json.dump([device.to_dict() for device in devices], f, indent=4)
            
def format_web(topology: Network)->None:
    """Launch the application and pass the Network object to the flask API with a POST request
    Args:
        topology (Network): Network topology
    """
    def run():
        app = create_app()
        app.run(host="0.0.0.0", port=5000, debug=False)
        
    def frontend():
        # Generate a random port for the frontend container
        frontend_port = random.randint(3001, 65535)
        
        # Stop any existing container with the same name
        try:
            subprocess.run(["docker", "stop", "nw-scanner-frontend"], 
                         capture_output=True, check=False)
            subprocess.run(["docker", "rm", "nw-scanner-frontend"], 
                         capture_output=True, check=False)
        except Exception as e:
            print(f"Warning: Could not stop existing container: {e}")
        
        # Start the frontend container with the random port
        try:
            cmd = [
                "docker", "run", "-d",
                "--name", "nw-scanner-frontend",
                "-p", f"{frontend_port}:3001",
                "ghcr.io/gchalard/nw-scanner-front:latest"
            ]
            print(f"🚀 Starting frontend container on port {frontend_port}...")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"✅ Frontend container started: {result.stdout.strip()}")
            return frontend_port
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to start frontend container: {e}")
            print(f"Error output: {e.stderr}")
            return None
    
    flask_thread = threading.Thread(target=run)
    flask_thread.daemon = True
    flask_thread.start()
    
    # Start frontend container and get the port
    frontend_port = frontend()
    
    max_retries = 30  # Maximum number of retries
    retry_delay = 1  # Delay between retries in seconds
    flask_ready = False
    frontend_ready = False

    print("Starting web services...")
    
    # Wait for Flask API to be ready
    for attempt in range(max_retries):
        try:
            response = requests.get("http://127.0.0.1:5000/api/health")
            if response.ok:
                print("✅ Flask API is ready.")
                flask_ready = True
                break
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1}: Waiting for Flask API... Error: {e}")
        time.sleep(retry_delay)
    
    # Wait for frontend to be ready
    if frontend_port:
        for attempt in range(max_retries):
            try:
                response = requests.get(f"http://127.0.0.1:{frontend_port}")
                if response.ok:
                    print(f"✅ Frontend is ready on port {frontend_port}.")
                    frontend_ready = True
                    break
            except requests.exceptions.RequestException as e:
                print(f"Attempt {attempt + 1}: Waiting for frontend on port {frontend_port}... Error: {e}")
            time.sleep(retry_delay)
    else:
        print("❌ Frontend container failed to start")
    
    if flask_ready and frontend_ready:
        try:
            topology_dict = topology.to_dict()
            print("📊 Sending topology to API:")
            print(json.dumps(topology_dict, indent=4))
            
            # Check for vulnerabilities in the data
            total_vulns = 0
            for device in topology_dict.get("clients", []):
                vulns = device.get("vulnerabilities", [])
                if vulns:
                    print(f"Device {device.get('ip')} has {len(vulns)} vulnerabilities")
                    total_vulns += len(vulns)
            
            router_vulns = topology_dict.get("router", {}).get("vulnerabilities", [])
            if router_vulns:
                print(f"Router has {len(router_vulns)} vulnerabilities")
                total_vulns += len(router_vulns)
            
            print(f"Total vulnerabilities found: {total_vulns}")
            
            response = requests.post("http://127.0.0.1:5000/api/network", json=topology_dict)
            print("Server response:", response.status_code, response.text)
            
            # Open web browser
            print("🌐 Opening web browser...")
            webbrowser.open(f"http://localhost:{frontend_port}")
            print("✅ Web application launched successfully!")
            print("📱 You can now view the network topology in your browser.")
            print(f"🔗 Frontend URL: http://localhost:{frontend_port}")
            print("🔗 API URL: http://localhost:5000")
            
        except requests.exceptions.RequestException as e:
            print("Failed to connect to the server:", e)
    else:
        print("❌ Failed to start web services. Please check the logs above.")
    
    # Keep the main thread alive
    try:
        flask_thread.join()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down web services...")
        # Clean up the frontend container
        try:
            subprocess.run(["docker", "stop", "nw-scanner-frontend"], 
                         capture_output=True, check=False)
            subprocess.run(["docker", "rm", "nw-scanner-frontend"], 
                         capture_output=True, check=False)
            print("🧹 Frontend container cleaned up")
        except Exception as e:
            print(f"Warning: Could not clean up frontend container: {e}")
        
    

def main(network: str, format: str, output: str = None)->None:
    nmap = nmap3.Nmap()
    network = ipaddress.IPv4Network(network)
    targets = get_targets(network)
    
    nmap_devices = nmap_scanner(network)
    
    arp_devices = parallel_icmp_scan(targets=targets, function=arp_ping_scan, description="Performing ARP Ping Scan")

    icmp_devices = parallel_icmp_scan(targets=targets, function=icmp_ping_scan, description="Performing ICMP Ping Scan")
    
    devices =  concatenate_devices(
        nmap_devices,
        arp_devices,
        icmp_devices
    )
  
    interface_name = get_if_name(network)
    gateway = get_gateway(interface=interface_name) if interface_name else None
    router = get_router(devices, gateway) if gateway else None    
    
    parallel_icmp_scan(targets=devices, function=lambda x: x.get_os(nmap), description="Performing OS Detection")
    
    parallel_icmp_scan(targets=devices, function=lambda x: x.set_hops(traceroute(x.ip)), description="Performing Traceroute")
    
    parallel_icmp_scan(targets=devices, function=lambda d: d.get_ports(port_range=range(1, 1024)), description="Performing Port Scan")
    
    # Perform vulnerability scanning
    parallel_icmp_scan(targets=devices, function=lambda d: scan_vulnerabilities(d, nmap), description="Performing Vulnerability Scan")
    
    # Create a default router if none found
    if router is None:
        # Use the first device as router or create a placeholder
        router = devices[0] if devices else Device(ip="192.168.1.1", hostname="Default Router")
    
    topology = Network(clients=[device for device in devices if device != router], router=router, address=network)
    
    # print(json.dumps(topology.to_dict(), indent=4))
    
    if format == "table":
        format_table(devices)
    
    if format == "json":
        format_json(devices, output)       
        
    if format == "web":
        format_web(topology)
        
def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", type=str, required=True, help="Network address in CIDR format")
    parser.add_argument("--format", type=str, choices=FORMATS, default="table", help="Output format")
    parser.add_argument("--output", type=str, help="Output file")
    
    args = parser.parse_args()
    
    main(
        network=args.network,
        format=args.format,
        output=args.output
    )

if __name__ == "__main__":
    
    cli()