# SOC Port Scanning Detection using Splunk

## 📌 Project Overview
This project demonstrates detection of port scanning attacks using Splunk SIEM and firewall logs.

---

## 🎯 Objective
To identify suspicious external IPs scanning multiple ports and generate alerts for monitoring.

---

## 🛠 Tools Used
- Splunk Enterprise
- FortiGate Firewall Logs

---

## 🔍 Detection Logic
- Filter denied traffic
- Identify external IPs
- Count unique destination ports
- Flag IPs accessing multiple ports

---

## 💻 SPL Query

index=* action=deny
| eval is_internal=if(
cidrmatch("10.0.0.0/8", srcip) OR
cidrmatch("172.16.0.0/12", srcip) OR
cidrmatch("192.168.0.0/16", srcip),
"yes","no"
)
| search is_internal="no"
| stats dc(dstport) as unique_ports count by srcip
| where unique_ports > 5


---

## 🚨 Alert Configuration
- Trigger when results > 0
- Runs every 5 minutes

---

## 📊 Dashboard Panels
- Traffic Trend
- Top Attacker IPs
- Targeted Ports
- Port Scan Detection

---

## 📸 Screenshots

### Detection Result
![Detection](screenshots/port-scan-detection-result.png)

### Time Correlation
![Correlation](screenshots/time-based-correlation.png)

### Alert Configuration
![Alert](screenshots/alert-configuration.png)

### Dashboard
![Dashboard](screenshots/soc-dashboard.png)

---
## 🧠 Skills Demonstrated
- Log Analysis
- SIEM (Splunk)
- Threat Detection
- Alert Configuration
- Dashboard Creation
- Incident Analysis

---


## 🧠 Conclusion
The project successfully detects reconnaissance activity (port scanning) and enables real-time monitoring using alerts and dashboards.
