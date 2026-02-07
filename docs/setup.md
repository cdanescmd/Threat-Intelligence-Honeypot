# Manual Deployment Log

This document records the exact sequence of commands used to provision the server.

### Phase 1: OS Hardening
1. **Login:**
   ```bash
   ssh root@<Vultr-IP>
2. **Update:**
   ```bash
   apt-get upgrade -y
3. **User Creation:**
   ```bash
   adduser <your-username>
Switched to new user for the remainder of the setup
   ```bash
su <your-username>
```
### Phase 2: T-Pot Installation

1. **Clone:**
git clone [https://github.com/telekom-security/tpotce](https://github.com/telekom-security/tpotce)
cd tpotce/iso/installer/

2. **Execution:**
   ```bash
   ./install.sh

3. Selections:
   - Install Type: h (Hive)

    Configured Web User & Password for Nginx/Kibana access.
   
### Phase 3: 
