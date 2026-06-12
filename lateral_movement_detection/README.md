# 🧠 Lateral Movement Detection Lab (Splunk SIEM)

## 📌 Overview
This lab simulates and detects **lateral movement behavior** using Splunk SIEM.  
Lateral movement is a common attacker technique where an adversary moves from one system to multiple internal systems after initial access.

This project demonstrates how SOC analysts can detect such behavior using log analysis and correlation queries.

---

## 🎯 Objective
To detect users accessing multiple systems (hosts) within a network, which may indicate:
- Compromised credentials
- Internal movement by an attacker
- Unauthorized access expansion

---

## ⚔️ Attack Simulation

Since this is a lab environment, lateral movement was simulated by generating synthetic log events representing user activity across multiple hosts.

### Example simulated logs:
user=subodh src=10.0.0.5 dest=hostA action=ssh success
user=subodh src=10.0.0.5 dest=hostB action=ssh success
user=subodh src=10.0.0.5 dest=hostC action=ssh success
