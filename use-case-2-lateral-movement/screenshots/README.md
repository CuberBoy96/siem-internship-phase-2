# 🟡 Use Case 2 — Lateral Movement Detection

![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-darkgreen)
![Tool](https://img.shields.io/badge/SIEM-Splunk-green)
![Use Case](https://img.shields.io/badge/Use%20Case-Lateral%20Movement-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

# 🎯 Objective

Detect lateral movement activity where an attacker remotely accesses a Windows machine using valid credentials and executes commands using Windows Management Instrumentation (WMI).

This use case focuses on identifying:

- Remote authentication attempts  
- Failed and successful logins  
- Remote command execution  
- PowerShell execution from remote session  

These behaviors indicate lateral movement across systems.

---

# 🧱 Lab Setup

| Component | Description |
|----------|-------------|
| 🖥️ Attacker Machine | Kali Linux |
| 🪟 Victim Machine | Windows 10 |
| 📊 SIEM | Splunk Free Edition |
| 📡 Logging | Windows Security Logs + Sysmon |
| 🛠️ Tools Used | wmiexec.py, smbclient |

---

# 🧪 Attack Simulation (Kali Side)

## Step 1 — Enumerate SMB Shares

From Kali Linux:

```bash
smbclient -L //192.168.1.10 -U internuser

```
Enter an incorrect password first to generate failed login logs.

Then enter the correct password to simulate successful authentication.

---

## Step 2 — Execute Remote Commands Using WMI

Run:
```bash
wmiexec.py internuser:Password123@192.168.1.10

```
This creates a remote shell session on the Windows machine.

---

## Step 3 — Execute System Commands

```Inside the remote session:

hostname
ipconfig
whoami

```
These commands simulate attacker reconnaissance activity.

---

## Step 4 — Launch PowerShell Remotely

```cmd
powershell.exe

```

This simulates PowerShell execution from a remote machine.

---

## 🖥️ Victim Behavior (Windows Logs)

Windows generates the following logs:

Event ID	Description
4625	Failed Login Attempt
4624	Successful Login
4688	Process Created

Sysmon logs:

Sysmon Event	Description
Event 1	Process Execution

---

## Parent-Child Process Chain

Expected process relationship:
```
wmiprvse.exe → cmd.exe → powershell.exe

```
This strongly indicates remote command execution.

---

## 🔎 Splunk Detection Queries

Detect Failed Login Attempts
```spl
index=* EventCode=4625
| stats count by Account_Name Source_Network_Address
| where count > 3

```
---

Detect Successful Remote Login
```spl
index=* EventCode=4624 LogonType=3
| table _time Account_Name Source_Network_Address

```
LogonType 3 indicates network logon.

---

Detect WMI-Based Execution
```spl
index=* EventCode=4688
Creator_Process_Name="*wmiprvse.exe"
| table _time New_Process_Name Account_Name

```

---

Detect Remote PowerShell Execution
```spl
index=* EventCode=4688
New_Process_Name="*powershell.exe"
| table _time Account_Name Creator_Process_Name

```

---

## 📊 Detection Logic Explanation

This detection monitors:

- Multiple failed login attempts
- Successful remote login
- Remote command execution
- PowerShell execution

When these events occur together, it strongly indicates:

🚨 Lateral Movement Activity

---

## 🧠 MITRE ATT&CK Mapping

|Category	  |Mapping   |
|-----------|-----------|
|🎯 Tactic	 |Lateral Movement |
|🧪 Technique	|T1021 — Remote Services  |
|🧪 Technique	|T1047 — Windows Management Instrumentation  |

---

## ⚠️ False Positives

Possible legitimate activities:

- IT administrators managing systems remotely
- Patch management systems
- Remote troubleshooting tools
- Scheduled maintenance tasks

Validation Steps:

- Verify source IP address
- Confirm administrator identity
- Check maintenance schedules

---

## 🚨 Alert Severity

HIGH

Reason:

Lateral movement allows attackers to spread across the network and compromise additional systems.

---

## 🔍 Investigation Playbook

SOC Analyst should:

- Identify source IP address
- Identify user account used
- Review failed login attempts
- Analyze executed commands
- Verify remote activity authorization
- Disable compromised account
- Monitor affected system

---

## 📁 Folder Structure
```
use-case-2-lateral-movement/
│
├── detection-logic/
│   └── lateral_movement_detection.spl
|
├── screenshots/
│   ├── smb-login-attempt.png
│   ├── wmiexec-session.png
│   ├── powershell-remote.png
│   ├── splunk-query-result.png
│   └── alert-triggered.png
│
└── README.md

```

---

## 📸 Screenshot Checklist

Capture the following:

- ✅ SMB login attempts
- ✅ Failed login events
- ✅ Successful login events
- ✅ Remote command execution
- ✅ PowerShell execution
- ✅ Splunk detection query results
- ✅ Alert triggered

---

## 🧾 Detection Logic File

Create file:

detection-logic/lateral_movement_detection.spl

Add:

```spl
index=* (EventCode=4624 OR EventCode=4625 OR EventCode=4688)
| table _time EventCode Account_Name Source_Network_Address New_Process_Name

```

---

## 🧪 Testing Validation

Verify:

- Failed login attempts occur
- Successful login occurs
- Remote commands executed
- Logs visible in Splunk
- Detection query returns results
- Alert triggers successfully


---

## 📊 Expected Logs 

You should observe:

- EventCode=4625 → Failed Login  
- EventCode=4624 → Successful Login  
- EventCode=4688 → Process Created  
- Sysmon Event 1 → Process Execution  

---

## 🏁 Final Outcome

After completing this use case:

- ✅ Lateral movement simulated
- ✅ Windows logs generated
- ✅ Logs forwarded to Splunk
- ✅ Detection query created
- ✅ Alert triggered successfully

This demonstrates real-world lateral movement detection capability in a SOC environment.

---

