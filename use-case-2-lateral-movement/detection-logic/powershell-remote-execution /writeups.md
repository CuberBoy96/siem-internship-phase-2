# 🛡️ Detection Engineering Lab: PowerShell Execution Detection via WMI — The "Liquid Gold" Playbook

![MITRE](https://img.shields.io/badge/MITRE-T1047-red)
![Technique](https://img.shields.io/badge/Technique-PowerShell%20over%20WMI-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![Status](https://img.shields.io/badge/Detection-Working-success)

---

## 📌 Project Overview

**PowerShell** is one of the most widely abused tools during post-exploitation.

Attackers favor PowerShell because it is:

- ✔️ Built into Windows  
- ✔️ Powerful  
- ✔️ Trusted  
- ✔️ Difficult to detect without proper logging  

This lab demonstrates how to detect **PowerShell commands executed remotely via WMI**, a classic **Living-off-the-Land (LOLBins)** technique.

---

## 🧪 Lab Architecture
```
Kali Linux (Attacker)
│
│ Impacket-WMIExec
▼
Windows Target System
│
│ PowerShell Execution
▼
Process Creation Logs
│
▼
Splunk SIEM
│
▼
PowerShell Detection 🚨

```

---

## ⚔️ Phase 1: Attack Simulation (Remote Execution)

In this lab, we simulated an attacker using **Impacket-WMIExec** to run a remote PowerShell command.

This technique allows attackers to:

- Execute remote commands
- Perform reconnaissance
- Download malware
- Maintain stealthy access

---

## 💻 Attack Execution

Executed from the Kali Linux attacker machine:

```bash
# Executing PowerShell remotely via WMI
impacket-wmiexec abhay:CB@i510400f@10.193.10.80 "powershell.exe -Command whoami"

```
---
## ✅ Result

Target system executed:
```
desktop-k7ml152\abhay

```
- ✔️ Remote command executed
- ✔️ PowerShell launched
- ✔️ Identity confirmed

---
## 📂 Phase 2: The Data Decoder (Field Mapping)

To detect activity reliably, logs from Windows Security (4688) and Sysmon (Event 1) must be normalized.

## 🧩 Field Normalization Mapping

|Information	|Windows 4688	|Sysmon 1	|Universal Alias |
|-------------|-------------|---------|----------------|
|New Process	|New_Process_Name	|Image	|ProcName |
|Parent Process	|Creator_Process_Name	|ParentImage	|Parent |
|Command Line	|Process_Command_Line	|CommandLine	|CmdLine |
|User Account	|Account_Name	|TargetUserName	|User |

---
## 🏆 Phase 3: High-Fidelity Detection (Splunk)

We created two detection queries:

- 1️⃣ PowerShell-specific detection
- 2️⃣ Universal WMI-based detection

---
## 🔍 Detection Query 1 — PowerShell-Specific

Detects when powershell.exe is launched.
```spl
index=* (EventCode=4688 OR EventCode=1)

New_Process_Name="*powershell.exe"

| table _time,
         Account_Name,
         New_Process_Name,
         Creator_Process_Name

```

---
## 💎 Detection Query 2 — Universal WMI Hunter

Detects PowerShell launched via wmiprvse.exe.

This is the hallmark of remote execution.
```spl
index=* (EventCode=4688 OR EventCode=1)

| eval Parent = coalesce(Creator_Process_Name,
                         ParentImage,
                         ParentProcessName)

| eval Child  = coalesce(New_Process_Name,
                         Image,
                         NewProcessName)

| eval User   = coalesce(Account_Name,
                         user,
                         TargetUserName)

| search Parent="*wmiprvse.exe"
        AND Child="*powershell.exe"

| table _time,
         User,
         Parent,
         Child

| sort - _time

```

---
## 📊 Phase 4: Lab Results & Observations

Splunk dashboard:
```
PowerShell Execution Detection

```
Successfully captured remote execution activity.

---
## 🔎 Observed Results

|Metric	|Value |
|-------|------|
|Total Events	|3 |
|Timeline	|12:44:07 |
|Parent Process	|wmiprvse.exe |
|Child Process	|powershell.exe |

---
## 🚨 Key Finding
```
wmiprvse.exe → powershell.exe
```
Confirms:

- ✔️ Remote execution
- ✔️ WMI-based execution
- ✔️ Suspicious activity

---
## 🛠️ Troubleshooting & Ground Truth

If searches return no results, check these:

## 1️⃣ Enable Process Creation Logging

Run:
```cmd
auditpol /set /subcategory:"Process Creation" /success:enable

```
## 2️⃣ Enable Command Line Logging

Enable:
```
Include command line in process creation events
```
Via:
```
Group Policy Editor
```
Path:
```
Computer Configuration
 → Administrative Templates
 → System
 → Audit Process Creation
```
## 3️⃣ Verify Logs Locally

Check:
```
eventvwr.msc
```
Navigate:
```
Windows Logs → Security
```
Confirm:
```
Event ID 4688 exists
```
## 4️⃣ Verify Sysmon Status

Check:
```
sc query sysmon
```
Sysmon improves:

- ✔️ Command visibility
- ✔️ Execution context
- ✔️ Payload analysis

---
## 🗺️ MITRE ATT&CK Mapping

|Technique	|ID	|Description |
|-----------|---|------------|
|Windows Management Instrumentation	|T1047	|Remote execution |
|PowerShell	|T1059.001	|Command execution |
|Living off the Land	|T1218	|Native tool abuse |

---
## 🚩 Indicators of Compromise (IOCs)

Watch for:

- ⚠️ wmiprvse.exe spawning powershell.exe
- ⚠️ Remote PowerShell execution
- ⚠️ Suspicious command arguments
- ⚠️ Unexpected admin activity

---
## 🛡️ Defensive Recommendations

Improve visibility and prevention:

- ✔️ Enable PowerShell logging
- ✔️ Monitor parent-child processes
- ✔️ Deploy Sysmon
- ✔️ Restrict remote WMI access
- ✔️ Alert on PowerShell usage

---
## 🧠 Key Takeaway

The process chain
```
wmiprvse.exe → powershell.exe
```
is a strong indicator of remote WMI-based PowerShell execution.

Combining:

- ✔️ Parent-child analysis
- ✔️ Command-line visibility
- ✔️ Process monitoring

Creates high-confidence detection.

---
## 🏁 Lab Conclusion

By analyzing:

- ✔️ Remote process execution
- ✔️ Parent-child relationships
- ✔️ Command-line arguments

We successfully built a detection method capable of identifying PowerShell-based remote attacks via WMI.

This technique is widely used in:

- 🛑 Lateral movement
- 🛑 Post-exploitation
- 🛑 Persistence

---
## ✍️ Author

Abhay

🔐 Detection Engineering
🧠 Threat Hunting
📊 SIEM Engineering

---
