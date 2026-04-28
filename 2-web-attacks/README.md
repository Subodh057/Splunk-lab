# Web Attack Detection using Nginx Logs (Splunk)

## Objective
Detect suspicious web activity such as scanning and abnormal traffic using nginx access logs in Splunk.

---

## Log Source
- /var/log/nginx/access.log

---

## Description
This project analyzes web server logs to identify potential attacks such as page scanning and abnormal traffic patterns. It focuses on detecting suspicious behavior based on HTTP status codes and request frequency.

---
## MITRE ATT&CK Mapping

* Tactic: Reconnaissance (TA0043)
* Technique: Active Scanning (T1595)
* Tactic: Discovery (TA0007)
* Technique: File and Directory Discovery (T1083)

Explanation:
The repeated 404 requests and endpoint probing align with T1595 (Active Scanning), where attackers actively probe web applications to discover valid paths and vulnerabilities.

## Detection Logic
- Monitor HTTP 404 responses (page not found)
- Identify repeated requests from same IP
- Detect abnormal traffic spikes
- Track access to sensitive endpoints (e.g., /admin)

---

## Sample Detection Query
```spl
index=main source="/var/log/nginx/access.log" 404
| rex "^(?<ip>\S+)"
| stats count by ip
| where count > 5
