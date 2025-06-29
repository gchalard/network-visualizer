from flask import request, jsonify
from typing import List

from src.classes import Network, Device, Port

def create_ports(ports: List[str])->List[Port]:
    print(ports)
    results: List[Port] = list()
    for port_str in ports:
        protocol, number = port_str.split('/')
        results.append(Port(number=int(number), protocol=protocol))
    return results

class NetworkController:
    network: Network = None
    
    def set_network(self, network: Network):
        self.network = network
        
    def get_network(self):
        return jsonify(self.network.to_dict()), 200
    
    def create_network(self):
        data = request.get_json()        
        
        clients = [
            Device(
                ip=device.get("ip", None),
                mac=device.get("mac", None),
                hostname=device.get("hostname", None),
                os=device.get("os", None),
                os_family=device.get("os_family", None),
                ports=create_ports(device.get("ports", list())),
                hops=device.get("hops", None)
            )
            for device in data.get("clients", list())
        ]
        
        router = Device(
            ip=data.get("router", dict()).get("ip", None),
            mac=data.get("router", dict()).get("mac", None),
            hostname=data.get("router", dict()).get("hostname", None),
            os=data.get("router", dict()).get("os", None),
            os_family=data.get("router", dict()).get("os_family", None),
            ports=create_ports(data.get("router", dict()).get("ports", list())),
            hops=data.get("router", dict()).get("hops", None)
        )
        
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
        