# Cybersecurity Lab Environment

A comprehensive cybersecurity testing environment using Multipass VMs with vulnerable services for educational purposes.

## Quick Setup
```bash
   git clone https://github.com/manzolo/cybersecurity-lab
   cd cybersecurity-lab
```

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
| `./lab.sh` | Interactive menu |
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

## Screenshoot
<img width="759" height="539" alt="image" src="https://github.com/user-attachments/assets/629d546a-616b-4d23-9f4f-621705a57a75" />

<img width="828" height="850" alt="image" src="https://github.com/user-attachments/assets/ac7a2725-31e9-4cc5-9ef0-338516dc133b" />

<img width="828" height="658" alt="image" src="https://github.com/user-attachments/assets/101955fa-837d-4a71-9e42-d867453294e1" />

<img width="828" height="658" alt="image" src="https://github.com/user-attachments/assets/be5eaf84-db08-49e8-bb49-f9c7fbecaeef" />

<img width="828" height="658" alt="image" src="https://github.com/user-attachments/assets/f3d34108-5150-418d-97bb-2a51bddaae98" />

<img width="936" height="760" alt="image" src="https://github.com/user-attachments/assets/e83f79bc-cfaa-4f9a-bd47-29971a2d6d43" />

<img width="936" height="636" alt="image" src="https://github.com/user-attachments/assets/77e79261-e6c1-4c56-88c1-4f3109fe8308" />

<img width="1085" height="321" alt="image" src="https://github.com/user-attachments/assets/1c3691a0-52b9-463a-afb4-1a5fbc48fb85" />

<img width="1085" height="321" alt="image" src="https://github.com/user-attachments/assets/5a37e135-6f9f-430d-9af3-2b8e27c923ed" />

<img width="1085" height="659" alt="image" src="https://github.com/user-attachments/assets/1a679147-e4fb-420c-a317-97a02b99b8d9" />

