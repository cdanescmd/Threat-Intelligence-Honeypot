# Threat Intelligence Honeypot
## Project Overview
A containerized honeypot deployment hosted on Vultr using Ubuntu server. This project demonstrates the orchestration of multiple security sensors to capture, analyze, and visualize global threat actor behavior in real-time.
## System Architecture
## Technical Implementation Details
## Component | Specification
Cloud Provider | Vultr (High-Performance Compute)
Host: | Ubuntu 22.04 LTS
Container Engine | Docker & Docker Compose
Firewall | Vultr Stateless Network Firewall
Analytics | ELK Stack (Elasticsearch, Logstash, Kibana)
## Security & OPSEC Posture
To maintain a secure posture and protect the underlying infrastructure, the following controls were implemented:
- Default-Deny Firewall: All ports are closed by default. Only specific honeypot "bait" ports are open to the public.
- Administrative Whitelisting: Management interfaces (SSH, Kibana)
- 
