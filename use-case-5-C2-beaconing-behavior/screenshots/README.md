# 🔴 Use Case 5 — Command-and-Control (C2) Beaconing Detection

![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-darkgreen)
![Tool](https://img.shields.io/badge/SIEM-Splunk-green)
![Use Case](https://img.shields.io/badge/Use%20Case-C2%20Beaconing-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

# 🎯 Objective

Detect Command-and-Control (C2) beaconing behavior where an infected machine repeatedly connects to an attacker-controlled server at regular intervals.

This use case focuses on identifying:

- Repeated outbound network connections  
- Periodic beaconing traffic  
- Suspicious communication to external hosts  
- Potential malware command-and-control activity  

Such activity commonly indicates compromised systems communicating with attacker infrastructure.

---

# 🧱 Lab Setup

| Component | Description |
|----------|-------------|
| 🖥️ Attacker Machine | Kali Linux |
| 🪟 Victim Machine | Windows 10 |
| 📊 SIEM | Splunk Free Edition |
| 📡 Logging | Sysmon + Windows Firewall Logs |
| 🛠️ Tools Used | Netcat (nc), PowerShell |

---

# 🧪 Attack Simulation (Kali Side)

## Step 1 — Start Netcat Listener (C2 Server)

On Kali Linux:

```bash
nc -lvnp 4444

```
This simulates an attacker-controlled command-and-control server.

---

## Step 2 — Create Beacon Script on Windows

On Windows victim:

Open PowerShell and run:

```powershell
while ($true) {
    Test-NetConnection 192.168.1.20 -Port 4444
    Start-Sleep -Seconds 10
}

```
This simulates beaconing every 10 seconds.

---

## Step 3 — Observe Incoming Connections

On Kali:

You should see repeated connections from the Windows machine.

This confirms simulated C2 behavior.

---

## 🖥️ Victim Behavior (Windows Logs)

Windows generates:

|Source    |Event ID	    | Description  |
|----------|--------------|--------------|
|Windows   |5156	        |Network Connection Allowed   |
|Sysmon    |Event 3	      |Network Connection  |

---

## Network Pattern Observed

Expected repeated pattern:

```
192.168.1.10 → 192.168.1.20:4444
192.168.1.10 → 192.168.1.20:4444
192.168.1.10 → 192.168.1.20:4444

```
Regular timing indicates beaconing behavior.

---

## 🔎 Splunk Detection Queries

Detect Repeated Connections to Same Destination
```spl
index=* EventCode=5156
| stats count by Source_Address Destination_Address Destination_Port
| where count > 10

```

Detect Frequent Sysmon Network Connections
```spl
index=* EventCode=3
| stats count by DestinationIp DestinationPort
| where count > 10

```

Detect Periodic Beaconing Pattern
```spl
index=* EventCode=3
| bin _time span=10s
| stats count by _time DestinationIp
| where count > 1

```

---

## 📊 Detection Logic Explanation

This detection identifies:

- Multiple outbound connections
- Same destination IP
- Same destination port
- Repeated timing intervals

Combined behavior indicates:

🚨 C2 Beaconing Activity

---

## 🧠 MITRE ATT&CK Mapping

|Category	|Mapping  |
|---------|---------|
|🎯 Tactic	| Command and Control  |
|🧪 Technique	| T1071 — Application Layer Protocol  |
|🧪 Technique	| T1041 — Exfiltration Over C2 Channel  |

---

## ⚠️ False Positives

Possible legitimate causes:

- Monitoring tools
- Backup software
- System health check tools
- Software update services

Validation Steps:

- Verify destination IP reputation
- Check application generating traffic
- Analyze connection frequency

🚨 Alert Severity

CRITICAL

Reason:

Beaconing behavior strongly indicates malware communication with attacker infrastructure.

---

## 🔍 Investigation Playbook

SOC Analyst should:

- Identify infected host
- Identify destination IP
- Check threat intelligence reputation
- Isolate infected system
- Capture memory and logs
- Remove malicious software
- Monitor for reinfection

---

## 📁 Folder Structure
```
use-case-5-c2-beaconing-behavior/
│
├── screenshots/
│   ├── netcat-listener.png
│   ├── beacon-script.png
│   ├── repeated-connections.png
│   ├── splunk-query-result.png
│   └── alert-triggered.png
│
├── detection-logic/
│   └── c2_beacon_detection.spl
│
├── writeups/
│   └── c2-beacon-analysis.md
│
└── README.md

```

---

## 📸 Screenshot Checklist

Capture:

- ✅ Netcat listener running
- ✅ Beacon script execution
- ✅ Repeated network connections
- ✅ Sysmon logs
- ✅ Splunk query results
- ✅ Alert triggered

---

## 📊 Expected Logs

You should observe:

- EventCode=5156 → Network Connection Allowed  
- Sysmon Event 3 → Network Connection  
- Repeated destination IP logs  

---

## 🏁 Final Outcome

After completing:

- ✅ Beacon simulation executed
- ✅ Repeated connections logged
- ✅ Logs forwarded to Splunk
- ✅ Detection created
- ✅ Alert triggered

---
This demonstrates Command-and-Control detection capability — a critical SOC skill.

---

# :calendar: Year

**2026**

---


