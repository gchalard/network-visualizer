from flask import request, jsonify
from typing import List
import json

from src.classes import Network, Device, Port, CPE, Vulnerability

def create_port(port: str)->Port:
    protocol, number = port.split('/')
    # Normalize protocol to uppercase
    protocol = protocol.upper()
    return Port(number=int(number), protocol=protocol)

def create_ports(ports: List[str])->List[Port]:
    print(ports)
    results: List[Port] = list()
    for port_str in ports:
        results.append(create_port(port_str))
    return results

class NetworkController:
    network: Network = None
    
    def set_network(self, network: Network):
        self.network = network
        
    def get_network(self):
        return jsonify(self.network.to_dict()), 200
    
    def create_network(self):
        try:
            data = request.get_json()
            print("Received network data:")
            print(json.dumps(data, indent=4))
            
            # Debug vulnerabilities in received data
            total_vulns = 0
            for device in data.get("clients", []):
                vulns = device.get("vulnerabilities", [])
                if vulns:
                    print(f"Client {device.get('ip')} has {len(vulns)} vulnerabilities")
                    total_vulns += len(vulns)
            
            router_vulns = data.get("router", {}).get("vulnerabilities", [])
            if router_vulns:
                print(f"Router has {len(router_vulns)} vulnerabilities")
                total_vulns += len(router_vulns)
            
            print(f"Total vulnerabilities in received data: {total_vulns}")
        except Exception as e:
            print(f"Error in create_network: {e}")
            return jsonify({"error": str(e)}), 500     
        
        clients: List[Device] = list()
        for device in data.get("clients", list()):
            try:
                vulnerabilties_dict = device.get("vulnerabilities", list())
                vulnerabilities: List[Vulnerability] = list()
                
                for vulnerabilty_dict in vulnerabilties_dict:
                    try:
                        cpes = [CPE(**cpe) for cpe in vulnerabilty_dict.get("cpes", list())]
                        vulnerabilty = Vulnerability(
                            port=create_port(vulnerabilty_dict.get("port", "tcp/0")),
                            service=vulnerabilty_dict.get("service", "unknown"),
                            product=vulnerabilty_dict.get("product", "unknown"),
                            version=vulnerabilty_dict.get("version", "unknown"),
                            cpes=cpes
                        )
                        
                        vulnerabilities.append(vulnerabilty)
                    except Exception as e:
                        print(f"Error creating vulnerability for device {device.get('ip')}: {e}")
                        continue
                
                clients.append(Device(
                    ip=device.get("ip", "0.0.0.0"),
                    mac=device.get("mac", None),
                    hostname=device.get("hostname", "Unknown"),
                    os=device.get("os", None),
                    os_family=device.get("os_family", None),
                    ports=create_ports(device.get("ports", list())),
                    hops=device.get("hops", None),
                    vulnerabilities=vulnerabilities
                ))
            except Exception as e:
                print(f"Error creating device {device.get('ip', 'unknown')}: {e}")
                continue
                
        
        router_vulns_dict = data.get("router", dict()).get("vulnerabilities", list())
        router_vulnerabilities: List[Vulnerability] = list()
        
        for vulnerabilty_dict in router_vulns_dict:
            try:
                cpes = [CPE(**cpe) for cpe in vulnerabilty_dict.get("cpes", list())]
                vulnerabilty = Vulnerability(
                    port=create_port(vulnerabilty_dict.get("port", "tcp/0")),
                    service=vulnerabilty_dict.get("service", "unknown"),
                    product=vulnerabilty_dict.get("product", "unknown"),
                    version=vulnerabilty_dict.get("version", "unknown"),
                    cpes=cpes
                )
                router_vulnerabilities.append(vulnerabilty)
            except Exception as e:
                print(f"Error creating router vulnerability: {e}")
                continue
        
        try:
            router = Device(
                ip=data.get("router", dict()).get("ip", "192.168.1.1"),
                mac=data.get("router", dict()).get("mac", None),
                hostname=data.get("router", dict()).get("hostname", "Router"),
                os=data.get("router", dict()).get("os", None),
                os_family=data.get("router", dict()).get("os_family", None),
                ports=create_ports(data.get("router", dict()).get("ports", list())),
                hops=data.get("router", dict()).get("hops", None),
                vulnerabilities=router_vulnerabilities
            )
        except Exception as e:
            print(f"Error creating router device: {e}")
            return jsonify({"error": f"Router creation failed: {str(e)}"}), 500
        
        network = Network(
            clients=clients,
            router=router,
            address=data.get("address", None)
        )
        
        self.set_network(network=network)
        
        return jsonify(
            {
                "message": "Network created successfully",
                **network.to_dict()
            }
        ), 201
        