import nmap3
from typing import List, Dict, Optional
from pydantic import BaseModel
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork
from pydantic_extra_types.mac_address import MacAddress

class Device(BaseModel):
    ip: IPvAnyAddress
    mac: Optional[MacAddress] = None
    hostname: str
    os: Optional[str] = None
    os_family: Optional[str] = None
    ports: Optional[List[int]] = None
    hops: Optional[List[str]] = None
    
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

        return os
    
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
            result["ports"] = self.ports
        
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