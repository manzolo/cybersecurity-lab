# Cybersecurity Lab Environment

A comprehensive cybersecurity testing environment using Multipass VMs with vulnerable services for educational purposes.

## Quick Setup

1. **First time setup:**
   ```bash
   ./lab.sh create             # Create the VMs and services
   ```

2. **Run tests:**
   ```bash
   ./lab.sh test               # Run comprehensive vulnerability tests
   ```

3. **Interactive testing:**
   ```bash
   ./lab.sh client             # Connect to vulnerable TCP server
   multipass shell attacker   # Direct access to attacker VM
   ```

## Usage

| Command | Description |
|---------|-------------|
| `./lab.sh create` | Create the complete lab environment |
| `./lab.sh test` | Run automated vulnerability tests |
| `./lab.sh client` | Interactive TCP client session |
| `./lab.sh status` | Show VM and service status |
| `./lab.sh destroy` | Clean up all resources |

## In Attacker VM

Once connected (`multipass shell attacker`), use:
- `lab-test` - Full test suite against target
- `lab-connect` - Interactive TCP client 
- `lab-logs` - View recent logs

## Requirements

- Multipass (https://multipass.run/)
- 4GB RAM minimum
- 20GB disk space

**Educational Use Only**: This environment is for learning cybersecurity concepts in a controlled setting.
