# SSH Brute Force Detection (Splunk)

## Objective
Detect brute-force login attempts using SSH logs in Splunk.

## Log Source
- /var/log/auth.log

## Description
This project analyzes SSH authentication logs to identify repeated failed login attempts, which indicate brute-force attacks.

## Detection Logic
- Monitor failed SSH login attempts
- Extract attacker IP address
- Count repeated attempts
- Trigger alert if threshold exceeded

## Splunk Queries

### Basic Detection

index=main sshd "Failed password"


### IP Extraction

index=main sshd "Failed password"
| rex "from (?<ip>\d+.\d+.\d+.\d+)"
| stats count by ip


### Brute Force Detection

index=main sshd "Failed password"
| rex "from (?<ip>\d+.\d+.\d+.\d+)"
| stats count by ip
| where count > 5

## Screenshots

### Failed Login Attempts
![Failed Logs](screenshots/failed_logs.png)

### IP Analysis
![IP Analysis](screenshots/ip_analysis.png)

### Brute Force Detection
![Brute Force](screenshots/brute_force.png)


## Outcome
Successfully detected brute-force attempts by identifying multiple failed login attempts from the same IP.

## Tools Used
- Splunk Enterprise
- Linux (Ubuntu)
- SSH
