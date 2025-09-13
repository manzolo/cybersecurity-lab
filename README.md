# Cybersecurity Lab Environment

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)](https://multipass.run/)
[![Version](https://img.shields.io/badge/Version-3.3-green)](https://github.com/manzolo/cybersecurity-lab)

A comprehensive, modular cybersecurity testing environment using Multipass VMs with intentionally vulnerable services designed for hands-on educational purposes.

## 🎯 Overview

This project creates a controlled, isolated environment where students and cybersecurity professionals can practice penetration testing techniques safely. It features two VMs: an **Attacker** machine with testing tools and a **Target** machine running vulnerable services.

### Key Features

- **🔧 Modular Architecture**: Separated scripts, services, and templates for easy maintenance
- **🎨 Dynamic MOTD System**: Immersive ASCII art banners with real-time system information
- **🛠️ Advanced Testing Tools**: Port scanner, web fuzzer, interactive client with exploitation hints
- **📊 Comprehensive Logging**: Structured logs with JSON export capabilities  
- **⚡ Granular Management**: Update individual components without VM recreation
- **🎓 Educational Focus**: Built-in guidance and security reminders

## 🚀 Quick Setup

```bash
git clone https://github.com/manzolo/cybersecurity-lab
cd cybersecurity-lab
```

### Prerequisites

- [Multipass](https://multipass.run/) - Cross-platform VM manager
- 4GB RAM minimum (8GB recommended)
- 20GB free disk space
- Linux, macOS, or Windows with WSL

### Initial Setup

1. **Create the complete environment:**
   ```bash
   ./lab.sh create             # Creates VMs, deploys scripts, configures services
   ```

2. **Run automated vulnerability tests:**
   ```bash
   ./lab.sh test               # Comprehensive security assessment
   ```

3. **Access interactive testing:**
   ```bash
   ./lab.sh client             # Connect to vulnerable TCP server
   multipass shell attacker   # Direct access to attacker VM
   ```

## 📖 Usage Guide

### Main Commands

| Command | Description |
|---------|-------------|
| `./lab.sh` | Launch interactive menu |
| `./lab.sh create` | Create complete lab environment |
| `./lab.sh test` | Run automated vulnerability tests |
| `./lab.sh client` | Interactive TCP client session |
| `./lab.sh status` | Show detailed VM and service status |
| `./lab.sh destroy` | Clean up all resources |

### Advanced Management

| Command | Description |
|---------|-------------|
| `./lab.sh update-scripts` | Update Python scripts without VM recreation |
| `./lab.sh update-services` | Update systemd service configurations |
| `./lab.sh update-motd` | Refresh dynamic welcome messages |
| `./lab.sh restart-services` | Restart all lab services |
| `./lab.sh service-status` | Detailed service health check |
| `./lab.sh preview-motd` | Preview welcome screens for both VMs |

### Attacker VM Tools

Once connected to the attacker VM (`multipass shell attacker`), use these aliases:

- `lab-help` - Show all available lab commands
- `lab-test` - Run comprehensive vulnerability test suite
- `lab-connect` - Interactive TCP client with exploitation hints
- `lab-scan <ip>` - Advanced port scanner with service detection
- `lab-web <ip>` - Web vulnerability fuzzer (XSS, directory traversal)
- `lab-logs` - View recent attack logs and statistics

## 🎯 Implemented Vulnerabilities

### TCP Server (Port 9000)
- **Command Injection**: `exec` command executes arbitrary system commands
- **Directory Traversal**: `file` command reads arbitrary files
- **Information Disclosure**: Various commands leak system information

### Web Application (Port 8080)
- **Cross-Site Scripting (XSS)**: `/echo` endpoint reflects input without sanitization
- **Directory Traversal**: `/file` endpoint allows reading arbitrary files
- **Remote Code Execution**: `/exec` endpoint executes system commands
- **Information Disclosure**: `/config`, `/debug`, and `/info` endpoints

### Testing Examples

```bash
# XSS Testing
curl 'http://target_ip:8080/echo?msg=<script>alert(1)</script>'

# Directory Traversal
curl 'http://target_ip:8080/file?name=../../../etc/passwd'

# Command Injection via TCP
nc target_ip 9000
> exec whoami
> file /etc/passwd
```

## 🏗️ Project Structure

```
cybersecurity-lab/
├── lab.sh                    # Main orchestration script
├── README.md                 # This documentation
├── config/                   # Generated configurations (auto-created)
├── logs/                     # System logs (auto-created)
├── scripts/                  # Modular bash components
│   ├── menu.sh              # Interactive menu system
│   ├── vm_management.sh     # VM lifecycle management
│   ├── testing.sh           # Test execution framework
│   └── utils.sh             # Common utilities
├── templates/                # Cloud-init templates
│   ├── target-cloud-init.yaml
│   └── attacker-cloud-init.yaml
├── target-scripts/           # Python scripts for target VM
│   ├── vulnerable-server.py  # Intentionally vulnerable TCP server
│   ├── web-server.py         # Vulnerable web application
│   └── monitor.sh            # System monitoring script
├── attacker-scripts/         # Python scripts for attacker VM
│   ├── port-scanner.py       # Advanced port scanner
│   ├── connection-tester.py  # Connection reliability tester
│   ├── interactive-client.py # Interactive exploitation client
│   └── web-fuzzer.py        # Web vulnerability fuzzer
└── services/                 # Systemd service definitions
    ├── vulnerable-server.service
    ├── vulnerable-web.service
    └── target-monitor.service
```

## 🎓 Learning Objectives

This lab environment is designed to teach:

- **Network Reconnaissance**: Port scanning and service enumeration
- **Vulnerability Assessment**: Automated and manual vulnerability discovery
- **Web Application Security**: XSS, directory traversal, and injection attacks
- **System Exploitation**: Command injection and privilege escalation techniques
- **Logging and Monitoring**: Understanding attack patterns and detection
- **Secure Development**: Learning from intentionally vulnerable code

## 🖼️ Screenshots

### Attacker VM Welcome Screen
<img width="759" height="539" alt="Attacker VM MOTD with ASCII art and system information" src="https://github.com/user-attachments/assets/629d546a-616b-4d23-9f4f-621705a57a75" />

### Interactive Testing Suite
<img width="828" height="850" alt="Comprehensive vulnerability testing interface" src="https://github.com/user-attachments/assets/ac7a2725-31e9-4cc5-9ef0-338516dc133b" />

### Web Vulnerability Scanner
<img width="828" height="658" alt="Web fuzzer detecting XSS and directory traversal" src="https://github.com/user-attachments/assets/101955fa-837d-4a71-9e42-d867453294e1" />

### Port Scanner Results
<img width="828" height="658" alt="Advanced port scanning with service detection" src="https://github.com/user-attachments/assets/be5eaf84-db08-49e8-bb49-f9c7fbecaeef" />

### Interactive TCP Client
<img width="828" height="658" alt="Interactive client with exploitation hints" src="https://github.com/user-attachments/assets/f3d34108-5150-418d-97bb-2a51bddaae98" />

### Service Management Interface
<img width="936" height="760" alt="Detailed service status and management" src="https://github.com/user-attachments/assets/e83f79bc-cfaa-4f9a-bd47-29971a2d6d43" />

### System Status Overview
<img width="936" height="636" alt="Comprehensive system status dashboard" src="https://github.com/user-attachments/assets/77e79261-e6c1-4c56-88c1-4f3109fe8308" />

## 🔧 Advanced Usage

### Customizing Vulnerabilities

Edit the Python scripts in `target-scripts/` to modify or add vulnerabilities:

```python
# In target-scripts/web-server.py
elif parsed_path.path == '/my-custom-endpoint':
    self.serve_custom_vulnerability(query)
```

### Adding New Testing Tools

Place new scripts in `attacker-scripts/` and update with:

```bash
./lab.sh update-scripts
```

### Modifying Services

Edit systemd service files in `services/` and apply changes:

```bash
./lab.sh update-services
./lab.sh restart-services
```

## 🛡️ Security Notice

⚠️ **EDUCATIONAL USE ONLY**

This environment contains **intentional security vulnerabilities** and should:

- ✅ Only be used in isolated, controlled environments
- ✅ Never be deployed on production networks
- ✅ Be destroyed after use: `./lab.sh destroy`
- ✅ Only be used on systems you own or have explicit permission to test

## 🐛 Troubleshooting

### Common Issues

**VMs won't start:**
```bash
multipass info --all       # Check VM status
multipass purge           # Clean up orphaned VMs
```

**Services not running:**
```bash
./lab.sh service-status   # Check detailed service status
./lab.sh restart-services # Restart all services
```

**Scripts not working:**
```bash
./lab.sh update-scripts   # Redeploy all scripts
```

**Multipass issues:**
```bash
# On Ubuntu/Debian
sudo snap refresh multipass

# On macOS
brew upgrade --cask multipass
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Test your changes: `./lab.sh test`
4. Commit your changes: `git commit -m 'Add feature'`
5. Push to the branch: `git push origin feature-name`
6. Create a Pull Request

### Development Setup

```bash
git clone https://github.com/manzolo/cybersecurity-lab
cd cybersecurity-lab
./lab.sh create    # Test the environment
./lab.sh test      # Run the test suite
```

## 📄 License

This project is licensed under the MIT License

## 🙏 Acknowledgments

- Built with [Multipass](https://multipass.run/) by Canonical
- Inspired by various cybersecurity training platforms
- Educational methodology influenced by OWASP guidelines

## 📚 Educational Resources

For additional learning, check out:

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Security Training](https://www.sans.org/)
- [Cybersecurity Body of Knowledge](https://www.cybok.org/)

---

**🎓 Happy Ethical Hacking!**

*Remember: The best way to learn cybersecurity is through hands-on practice in controlled environments like this one.*