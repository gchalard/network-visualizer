
import concurrent.futures
import nmap3
from pydantic import BaseModel, AnyUrl
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork
from pydantic_extra_types.mac_address import MacAddress
from typing import List, Dict, Optional
import socket

def scan_port(target: str, port: int, protocol: str, timeout: int = 1)->int|None:
    if protocol == "TCP":
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((str(target), port))
            return port
        except Exception as e:
            return None
    elif protocol == "UDP":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                # UDP port scanning is generally less reliable than TCP
                # Here, we send an empty packet and check for an ICMP port unreachable message
                sock.sendto(b"", (str(target), port))
                data, _ = sock.recvfrom(1024)  # Try to receive data
                return port
        except Exception as e:
            return None

class Port(BaseModel):
    number: int
    protocol: str
    
    def __str__(self):
        return f"{self.protocol}/{self.number}"
    
class CPE(BaseModel):
    id: str
    cvss: str
    type: str
    ref: AnyUrl
    
    def to_dict(self)->Dict:
        return {
            "id": self.id,
            "cvss": self.cvss,
            "type": self.type,
            "ref": str(self.ref)
        }
    
class Vulnerability(BaseModel):
    port: Port
    service: str
    product: str
    version: str
    cpes: List[CPE]
    
    def to_dict(self)->Dict:
        return {
            "port": str(self.port),
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "cpes": [cpe.to_dict() for cpe in self.cpes]
        }
        

class Device(BaseModel):
    ip: IPvAnyAddress
    mac: Optional[MacAddress] = None
    hostname: str
    os: Optional[str] = None
    os_family: Optional[str] = None
    ports: Optional[List[Port]] = None
    hops: Optional[List[str]] = None
    vulnerabilies: Optional[List[Vulnerability]] = None
    
    def get_ports(self, port_range: List[int]):
        open_ports: List[Port] = list()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(scan_port, self.ip, port, "TCP") for port in port_range
            ]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(Port(number=result, protocol="TCP"))
                    
            futures = [
                executor.submit(scan_port, self.ip, port, "UDP") for port in port_range
            ]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(Port(number=result, protocol="UDP"))
        self.ports = open_ports
    
    def get_os(self, nmap: nmap3.Nmap):
        result = nmap.nmap_os_detection(str(self.ip))

        # Check if the IP exists in the result
        if str(self.ip) not in result:
            return None

        # Check if "osmatch" key exists and is not empty
        os_match = result[str(self.ip)].get("osmatch", None)
        if not os_match:
            return None

        # Safely access the first OS match
        os = os_match[0]
        self.os = os.get("name", None)
        if "osclass" in os:
            self.os_family = os["osclass"].get("osfamily", None)
    
    def set_vulnerabilities(self, vulnerabilities: List[Vulnerability]):
        self.vulnerabilies = vulnerabilities
    
    def to_dict(self)->Dict:
        
        result = {
            "ip": str(self.ip),
            "hostname": self.hostname
        }
        
        if self.mac:
            result["mac"] = str(self.mac)
        
        if self.os:
            result["os"] = self.os
            
        if self.os_family:
            result["os_family"] = self.os_family
            
        if self.ports:
            result["ports"] = [str(port) for port in self.ports]
            
        if self.vulnerabilies:
            result["vulnerabilities"] = [vulnerability.to_dict() for vulnerability in self.vulnerabilies]
        
        return result
    
    def __hash__(self):
        return hash(self.ip) + hash(self.hostname)
    
    def __eq__(self, other):
        return self.ip == other.ip and self.hostname == other.hostname
    
    def set_hops(self, hops: List[str]):
        self.hops = hops
    

class Network(BaseModel):
    clients: List[Device]
    router: Device
    address: IPvAnyNetwork
    
    def to_dict(self)->Dict:
        return {
            "clients": [device.to_dict() for device in self.clients],
            "router": self.router.to_dict(),
            "address": str(self.address)
        }
    
class Interface(BaseModel):
    name: str
    ip: IPvAnyAddress