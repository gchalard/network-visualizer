from flask import request, jsonify

from classes import Network, Device

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
                ports=device.get("ports", None),
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
            ports=data.get("router", dict()).get("ports", None),
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
        