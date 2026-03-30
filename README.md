# SOC Port Scanning Detection using Splunk

## Objective
To detect port scanning activity from external attackers using Splunk SIEM.

## Tools Used
- Splunk Enterprise
- Firewall Logs (FortiGate)

## Detection Logic
- Identify external IPs
- Count unique destination ports
- Detect multiple port access attempts

## SPL Query
(index=* action=blocked OR action=failure)
| eval is_internal=if(
    cidrmatch("10.0.0.0/8", srcip) OR
    cidrmatch("172.16.0.0/12", srcip) OR
    cidrmatch("192.168.0.0/16", srcip),
    "yes","no"
)
| search is_internal="no"
| stats dc(dstport) as unique_ports count by srcip
| where unique_ports > 5

## Alerting
- Triggered when multiple ports accessed by same IP
- Scheduled every 5 minutes

## Dashboard
- Port scan trends
- Top attacker IPs
- Targeted ports

## Conclusion
Detected reconnaissance activity from external IPs targeting multiple ports. Alerts were configured for real-time monitoring.
