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
