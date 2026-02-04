# 🚧Threat Intelligence Honeypot🚧
## Project Overview
A containerized honeypot deployment hosted on Vultr using Ubuntu server. This project demonstrates the orchestration of multiple security sensors to capture, analyze, and visualize global threat actor behavior in real-time.
## System Architecture
<img src="./assets/honeypot_diagram.png" width="600"/>

## Technical Implementation Details

| Component | Specification |
| ------------- | ------------- |
| Cloud Provider  | Vultr (High-Performance Compute)  |
| Host  | Ubuntu 22.04 LTS  |
| Container Engine | Docker & Docker Compose |
Firewall | Vultr Stateless Network Firewall
Analytics | ELK Stack (Elasticsearch, Logstash, Kibana)
## Security & OPSEC Posture
To maintain a secure posture and protect the underlying infrastructure, the following controls were implemented:
- Default-Deny Firewall: All ports are closed by default. Only specific honeypot "bait" ports are open to the public.
- Administrative Whitelisting: Management interfaces (SSH, Kibana) are strictly restricted to a single authorized source IP, making them invisible to unauthorized scanners.
- Container Isolation: All honeypot services (Cowrie, Dionaea, etc.) run in isolated Docker containers, preventing attackers from interacting with the Ubuntu host system.
- Data Anonymization: In compliance with security best practices, all Network Layer identifiers (IPs) haven been abstracted in this documentation to focus on behavioral threat patterns.

## Honeypot Sensor Catalog
Cowrie (SSH/Telnet): Captured brute-force attempts and logged attacker command.
Dionaea: Intercepted network-wide malware propagation attempts (SMB/MSSQL).
Suricata: Provided signature-based Intrustion Detection (IDS) for all incoming traffic.
