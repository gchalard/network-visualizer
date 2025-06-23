import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import nmap3
import netifaces
from pathlib import Path
import prettytable
import requests
from scapy.all import ARP, Ether, ICMP, IP, srp, sr1, RandShort
from scapy.config import Conf
import socket
import threading
import time
from tqdm import tqdm
from typing import List, Optional
import webbrowser

### Custom imports for classes
from classes import Device, Interface, Network

### Custom imports for web application
from app.API.app import create_app

Conf.verb = 0

FORMATS = ["table", "json", "web"]

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
    
    flask_thread = threading.Thread(target=run)
    flask_thread.daemon = True
    flask_thread.start()
    
    max_retries = 30  # Maximum number of retries
    retry_delay = 1  # Delay between retries in seconds

    for attempt in range(max_retries):
        try:
            response = requests.get("http://127.0.0.1:5000/api/health")
            if response.ok:
                print("Successfully connected to the server.")
                break  # Exit the loop if the connection is successful
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1}: Failed to connect to the server. Retrying in {retry_delay} second(s)... Error: {e}")

        time.sleep(retry_delay)
    
    try:
        response = requests.post("http://127.0.0.1:5000/api/network", json=topology.to_dict())
        print("Server response:", response.status_code, response.text)
    except requests.exceptions.RequestException as e:
        print("Failed to connect to the server:", e)
    
    flask_thread.join()
        
    

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
  
    gateway = get_gateway(interface=get_if_name(network))
    router = get_router(devices, gateway)
    topology = Network(clients=[device for device in devices if device != router], router=router, address=network)
    print(json.dumps(topology.to_dict(), indent=4))
    
    
    parallel_icmp_scan(targets=devices, function=lambda x: x.get_os(nmap), description="Performing OS Detection")
    
    parallel_icmp_scan(targets=devices, function=lambda x: x.set_hops(traceroute(x.ip)), description="Performing Traceroute")
    
    if format == "table":
        format_table(devices)
    
    if format == "json":
        format_json(devices, output)       
        
    if format == "web":
        format_web(topology)

if __name__ == "__main__":
    
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