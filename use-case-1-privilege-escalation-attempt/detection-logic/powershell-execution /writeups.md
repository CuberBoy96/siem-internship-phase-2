# 🛡️ Remote Powershell / Process Execution Detection: The "Liquid Gold" Splunk Playbook
![MITRE](https://img.shields.io/badge/MITRE-T1047-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![Status](https://img.shields.io/badge/Detection-Working-success)

---
When an attacker moves laterally using **WMI**, they leave a specific digital footprint.  
This guide transforms raw logs into a **high-fidelity detection engine** for **Impacket-WMIExec** activity.

---
# 📌 Project Overview

This use case demonstrates how to **simulate and detect remote process execution**.

By monitoring **parent-child process relationships**, we can detect attackers performing **lateral movement**.

---

# 🧪 Lab Architecture

| Component | Description |
|----------|-------------|
| 🧑‍💻 Attacker | Kali Linux (Running `impacket-wmiexec`) |
| 🎯 Target | Windows Endpoint (Logging Enabled) |
| 📊 SIEM | Splunk (Log Aggregation & Detection) |

---

# ⚔️ Phase 1: The Attack Simulation

Attackers leverage **WMI (Windows Management Instrumentation)** because it is a legitimate administrative tool — making it perfect for **Living-off-the-Land attacks (LOLBins)**.

---

## 💻 The Command

Executed from the Kali attacker machine:

```bash
# Executing remote command via WMI
impacket-wmiexec abhay:CB@i510400fa@10.193.10.80 "whoami"

```

---
## ✅ The Result

The attacker receives a response from the target system:
```
desktop-k7ml152\abhay

```
✔️ Remote execution successful

---
## 🧠 Phase 2: The Detection Logic (The "Why")

Standard process monitoring is not enough.

We detect attacks by identifying suspicious Parent-Child process relationships.

🔗 Suspicious Process Chain

When WMIExec runs:
```
wmiprvse.exe → cmd.exe

```

---
What Happens Internally:

- 1️⃣ wmiprvse.exe starts
- 2️⃣ It spawns cmd.exe or powershell.exe
- 3️⃣ Commands execute remotely

---
## 🚨 Critical Detection Insight

wmiprvse.exe spawning cmd.exe is a major red flag for lateral movement.

---
## 🧩 Phase 3: The Troubleshooting Workflow

If your Splunk dashboard is empty — check these first.

---
## 1️⃣ Field Name Mismatch

Windows Security Logs and Sysmon use different field names.

|✨ Information	  |📂 Windows 4688	 |📊 Sysmon Event 1  |
|-----------------|------------------|----------------------|
|New Process	|New_Process_Name	|Image  |
|Parent Process	|Creator_Process_Name	|ParentImage  |
|User Account	|Account_Name	|TargetUserName  |

---
## 2️⃣ Enable Audit Policy

Windows does not log process creation by default.

Run this on Windows:
```cmd
auditpol /set /subcategory:"Process Creation" /success:enable

```

---
## 🏆 Phase 4: The "Universal" Hunter Query

This is your Liquid Gold Query.

It uses the coalesce() function to normalize field names across different log sources.

---
## 🧪 Detection Query
```
index=* (EventCode=4688 OR EventCode=1)

| eval Parent = coalesce(Creator_Process_Name, ParentImage, ParentProcessName)

| eval Child  = coalesce(New_Process_Name, Image, NewProcessName)

| eval User   = coalesce(Account_Name, user, TargetUserName)

| search Parent="*wmiprvse.exe*"

| table _time, User, Parent, Child

| sort - _time

```

---
## 📊 Phase 5: Detection Results

Splunk successfully detects suspicious activity.
- ✔️ Detection successful
- ✔️ Logs collected
- ✔️ Threat identified

---
## 🗺️ Phase 6: Strategic Mapping & IOCs
🎯 MITRE ATT&CK Framework
|Technique	|ID	 |Description  |
|-----------|----|-------------|
|Windows Management Instrumentation	|T1047	|Remote command execution via WMI |
|Remote Services	|T1021	|Lateral movement |
|Command Execution	|T1059	|Running commands via shell  |

---
## 🚩 Key Indicators of Compromise (IOCs) 

Look for:

- ⚠️ wmiprvse.exe spawning shell processes
- 🔁 Multiple processes in short timeframe
- 🕒 Administrative tools running at unusual hours
- 🌐 Remote execution behavior
- 🛡️ Defensive Recommendations

---
Improve your defensive posture:

- ✔️ Restrict Remote WMI
- ✔️ Enable Sysmon Logging
- ✔️ Monitor Privileged Accounts
- ✔️ Alert on unusual login sources
- ✔️ Investigate abnormal shell activity

---
## 🧠 Key Takeaway

Monitoring wmiprvse.exe spawning shell processes is one of the most reliable ways to detect WMI-based lateral movement.

---
## ✍️ Author

Abhay

🔐 Detection Engineering
🧠 Threat Hunting
📊 SIEM Engineering
