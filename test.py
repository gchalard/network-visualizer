import shlex
import xml.etree.ElementTree as ET
from nmap3 import Nmap
import json

def nmap_vulners_script(nmap: Nmap, target, vulners_script="--script vulners", args="-sV", timeout=None):
    """
    Perform an Nmap scan using the vulners script.

    :param target: Target IP or domain.
    :param vulners_script: The vulners script to use.
    :param args: Additional arguments for the Nmap command.
    :param timeout: Timeout for the scan.
    :return: Dictionary containing vulnerability information.
    """
    nmap.target = target
    vulners_args = "{target} {default}".format(target=target, default=vulners_script)

    if args:
        vulners_args += " {0}".format(args)

    vulners_command = nmap.default_command() + " " + vulners_args
    vulners_shlex = shlex.split(vulners_command)

    # Run the command and get the output
    output = nmap.run_command(vulners_shlex, timeout=timeout)

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
                print(f"Vulnerable service: {service.get('name')} {service.get('product')} v{service.get('version')} on port {port.get('protocol')}/{port.get('portid')}")
                
                vuln = {
                    'port': f"{port.get('protocol').upper()}/{port.get('portid')}",
                    'service': service.get('name'),
                    'product': service.get('product'),
                    'version': service.get('version'),
                    'cpes': []
                }
                
                cpes = vulners_script.findall("table/table")
                for cpe in cpes:
                    data = {
                        'id': cpe.find("elem[@key='id']").text,
                        'cvss': cpe.find("elem[@key='cvss']").text,
                        'type': cpe.find("elem[@key='type']").text,
                    }
                    data["ref"] = f"https://vulners.com/{data['type']}/{data['id']}"
                    vuln['cpes'].append(data)
                
                vulnerabilities.append(vuln)
                

    return vulnerabilities

nmap = Nmap()
results = nmap_vulners_script(nmap, "192.168.1.1", args="-sV")
print(results)
