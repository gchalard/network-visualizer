# NW-Scanner: Network Scanner and Visualizer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

A powerful network scanner and visualizer that combines ARP, ICMP, OS detection, traceroute, port scanning, and vulnerability scanning capabilities with an intuitive web interface.

## 🎥 Demo

https://github.com/gchalard/nw-scanner/assets/demo-nw-scanner.mp4

## ✨ Features

### 🔍 **Network Discovery**
- **ARP Ping Scanning**: Fast layer 2 network discovery using ARP requests
- **ICMP Ping Scanning**: Traditional ICMP echo request scanning
- **Nmap Integration**: Leverages nmap for comprehensive network enumeration
- **Automatic Interface Detection**: Automatically detects the correct network interface

### 🖥️ **OS Detection & Fingerprinting**
- **Operating System Detection**: Identifies OS family and specific versions
- **Service Enumeration**: Discovers running services and their versions
- **Device Classification**: Distinguishes between routers, servers, and workstations

### 🌐 **Network Topology**
- **Traceroute Analysis**: Maps network paths and hop counts
- **Gateway Detection**: Automatically identifies and analyzes network gateways
- **Topology Visualization**: Interactive web-based network topology display

### 🔌 **Port Scanning**
- **Comprehensive Port Analysis**: Scans common ports (1-1024) by default
- **Service Identification**: Detects running services and their versions
- **Protocol Support**: TCP and UDP port scanning capabilities

### 🛡️ **Vulnerability Assessment**
- **NSE Script Integration**: Uses nmap vulners script for vulnerability scanning
- **CVE Database**: Comprehensive vulnerability database integration
- **CVSS Scoring**: Risk assessment with Common Vulnerability Scoring System
- **Detailed Reports**: Detailed vulnerability reports with references and descriptions

### 🌐 **Web Interface**
- **Interactive Dashboard**: Modern React-based web interface
- **Real-time Visualization**: Dynamic network topology visualization
- **Vulnerability Details**: Detailed vulnerability information with CVE references
- **Responsive Design**: Works on desktop and mobile devices
- **Docker Integration**: Containerized frontend for easy deployment

### 📊 **Output Formats**
- **Table Format**: Human-readable tabular output
- **JSON Format**: Machine-readable JSON output for automation
- **Web Interface**: Interactive web-based visualization

## 🚀 Quick Start

### Prerequisites

Before installing NW-Scanner, ensure you have the following prerequisites:

#### 1. **Nmap Installation**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap

# CentOS/RHEL/Fedora
sudo dnf install nmap  # or sudo yum install nmap

# macOS
brew install nmap

# Verify installation
nmap --version
```

#### 2. **Vulners NSE Script**
The vulners script provides comprehensive vulnerability scanning capabilities:

```bash
# Download the vulners script
sudo wget -O /usr/share/nmap/scripts/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse

# Update nmap script database
sudo nmap --script-updatedb

# Verify the script is available
nmap --script vulners --script-args vulners.showall
```

#### 3. **Docker Installation**
Required for the web interface:

```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# CentOS/RHEL/Fedora
sudo dnf install docker  # or sudo yum install docker
sudo systemctl start docker
sudo systemctl enable docker

# macOS
brew install --cask docker

# Verify installation
docker --version
```

#### 4. **UV Package Manager**
Install UV for fast Python package management:

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or follow the official installation guide:
# https://docs.astral.sh/uv/getting-started/installation/
```

### Installation

#### System-wide Installation (Recommended)
```bash
# Install NW-Scanner system-wide
sudo uv pip install nw-scanner --system

# Verify installation
nw-scanner --version
```

#### Development Installation
```bash
# Clone the repository
git clone https://github.com/gchalard/nw-scanner.git
cd nw-scanner

# Install in development mode
uv pip install -e .

# Verify installation
python -m src.main --version
```

## 📖 Usage

### Basic Network Scan
```bash
# Scan a network and display results in table format
sudo nw-scanner --network 192.168.1.0/24 --format table

# Scan with JSON output
sudo nw-scanner --network 192.168.1.0/24 --format json --output results.json

# Launch web interface
sudo nw-scanner --network 192.168.1.0/24 --format web
```

### Advanced Usage Examples

#### Large Network Scanning
```bash
# Scan a /16 network (65,536 hosts)
sudo nw-scanner --network 10.0.0.0/16 --format json --output large_scan.json
```

#### Vulnerability-Focused Scan
```bash
# The scanner automatically includes vulnerability scanning
# Results will show CVE details, CVSS scores, and references
sudo nw-scanner --network 192.168.1.0/24 --format web
```

#### Custom Port Ranges
```bash
# Modify the port range in the source code for custom scanning
# Default range: 1-1024
# Edit src/classes.py -> Device.get_ports() method
```

## 🔧 Configuration

### Network Interface Selection
The scanner automatically detects the appropriate network interface based on the target network. For manual interface selection, modify the `get_if_name()` function in `src/main.py`.

### Port Scanning Configuration
To modify the default port range (1-1024), edit the `get_ports()` method in the `Device` class in `src/classes.py`.

### Vulnerability Scanning
The vulners script is automatically used for vulnerability scanning. Ensure the script is properly installed and the nmap script database is updated.

## 🏗️ Architecture

### Backend Components
- **Network Discovery**: ARP/ICMP scanning modules
- **OS Detection**: nmap-based OS fingerprinting
- **Port Scanning**: Comprehensive port enumeration
- **Vulnerability Assessment**: NSE script integration
- **API Server**: Flask-based REST API

### Frontend Components
- **React Application**: Modern web interface
- **Network Visualization**: Interactive topology display
- **Vulnerability Dashboard**: Detailed CVE information
- **Responsive Design**: Mobile-friendly interface

### Docker Integration
- **Containerized Frontend**: Isolated web application
- **Dynamic Port Allocation**: Automatic port assignment
- **Health Checks**: Service readiness monitoring

## 🛠️ Development

### Project Structure
```
nw-scanner/
├── src/
│   ├── app/
│   │   ├── API/          # Flask API backend
│   │   └── frontend/     # React frontend
│   ├── classes.py        # Core data models
│   └── main.py          # Main application logic
├── bake.hcl             # Docker build configuration
├── pyproject.toml       # Python package configuration
└── README.md           # This file
```

### Building from Source
```bash
# Clone and setup
git clone https://github.com/gchalard/nw-scanner.git
cd nw-scanner

# Install development dependencies
uv pip install -e ".[dev]"

# Run tests
pytest

# Build Docker image
docker buildx bake --file bake.hcl
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📋 Requirements

### System Requirements
- **Python**: 3.10 or higher
- **Nmap**: Latest version with NSE support
- **Docker**: For web interface deployment
- **Network Access**: Root/sudo privileges for network scanning

### Python Dependencies
- `python3-nmap`: Nmap Python bindings
- `scapy`: Network packet manipulation
- `pydantic`: Data validation
- `flask`: Web API framework
- `requests`: HTTP client library
- `netifaces`: Network interface information
- `tqdm`: Progress bars
- `prettytable`: Formatted output

## 🔒 Security Considerations

### Network Scanning
- **Legal Compliance**: Ensure you have permission to scan target networks
- **Rate Limiting**: Be mindful of network impact during scanning
- **Privilege Requirements**: Root/sudo access required for raw packet operations

### Vulnerability Data
- **CVE Information**: All vulnerability data is sourced from public CVE databases
- **Risk Assessment**: CVSS scores help prioritize remediation efforts
- **References**: Direct links to vulnerability details and patches

## 🙏 Acknowledgments

- **Nmap**: Network discovery and security auditing
- **Vulners**: Comprehensive vulnerability database
- **Scapy**: Network packet manipulation library
- **React**: Modern web interface framework
- **Flask**: Lightweight web framework

---

**Note**: This tool is designed for authorized network security testing and research. Always ensure you have proper authorization before scanning any network.
