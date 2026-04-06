# 🛡️ Detection Engineering Lab: Hunting Interactive WMIExec Sessions

![MITRE](https://img.shields.io/badge/MITRE-T1047-red)
![Technique](https://img.shields.io/badge/Technique-WMIExec%20Session-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![Status](https://img.shields.io/badge/Detection-Working-success)

---

# 📌 Project Overview

This project focuses on identifying the **digital footprint** left by **interactive WMIExec sessions**.

Unlike one-time command execution, an interactive session allows attackers to:

- Execute multiple commands
- Maintain temporary shell access
- Perform reconnaissance
- Move laterally across systems

By analyzing **process relationships**, we transform raw logs into **actionable intelligence**.

---

# 🧪 Lab Architecture
```
Kali Linux (Attacker)
│
│ Impacket-WMIExec
▼
Windows Target System
│
│ Interactive Commands
▼
Process Creation Logs
│
▼
Splunk SIEM
│
▼
Session Detection 🚨

```
---

## ⚔️ Phase 1: Attack Simulation (Interactive Session)

Unlike a single command execution, attackers may create a **semi-interactive WMI shell session**.

This allows them to run **multiple commands** in one authenticated session.

---

## 💻 Attack Execution

Executed from the Kali Linux attacker machine:

```bash
# Establishing semi-interactive shell session
impacket-wmiexec abhay:CB@i510400f@10.193.10.80

```
🧪 Command Execution Inside Session

After connection:
```cmd
whoami

```
## ---
✅ Result
```
desktop-k7ml152\abhay
```
- ✔️ Session successfully established
- ✔️ Interactive shell active

---
## 🧠 Phase 2: Detection Logic (The Footprint)

The key signature of WMIExec interactive sessions is:
```
wmiprvse.exe → cmd.exe

```
## 🔗 What Happens Internally

- 1️⃣ wmiprvse.exe starts
- 2️⃣ It spawns cmd.exe
- 3️⃣ Each command generates a new cmd.exe process
- 4️⃣ Multiple events appear in logs

---
## 🚨 Critical Insight

Multiple cmd.exe processes spawned by wmiprvse.exe strongly indicates an interactive WMI session.

---
## 📂 Phase 3: Field Normalization

Different log sources use different field names.

Normalization ensures reliable detection.

---
## 🧩 Field Normalization Mapping

|Information	|Standard Field	|Universal Alias |
|-------------|---------------|----------------|
|Process Name	|New_Process_Name	|ProcName  |
|Parent Process	|Creator_Process_Name	|Parent |
|User	|Account_Name	|User |

---
## 🏆 Phase 4: Splunk Detection Queries

We built two detection queries.

## 🔍 Detection Query 1 — Verified Lab Query

This query directly detects activity observed during the lab.
```spl
index=* (EventCode=4688 OR EventCode=1)

New_Process_Name="*cmd.exe"
Creator_Process_Name="*wmiprvse.exe"

| table _time,
         Account_Name,
         New_Process_Name,
         Creator_Process_Name
```
---
## 💎 Detection Query 2 — Universal Session Hunter

This version works across:

- ✔️ Sysmon
- ✔️ Windows Security Logs

---
```spl
index=* (EventCode=4688 OR EventCode=1)

| eval Parent = coalesce(ParentProcessName,
                         ParentImage,
                         Creator_Process_Name)

| eval ProcName = coalesce(NewProcessName,
                           Image,
                           process_name)

| search ProcName="*cmd.exe"
        AND Parent="*wmiprvse.exe"

| table _time,
         Account_Name,
         Parent,
         ProcName
```
---
## 📊 Phase 5: Lab Results & Observations

The Splunk dashboard:
```
wmiexec_session_detection

```
Successfully detected multiple session commands.

---
## 🔎 Observed Events

|Time	|Parent Process	|Child Process |
|-----|---------------|--------------|
|12:24:05	|wmiprvse.exe	|cmd.exe |
|12:24:14	|wmiprvse.exe	|cmd.exe |
|12:24:14	|wmiprvse.exe	|cmd.exe |

- ✔️ Multiple command executions detected
- ✔️ Interactive session confirmed

---
## 🛠️ Troubleshooting & Hunting Tips

If logs do not appear:

- 1️⃣ Enable Process Creation Logging

Run:
```cmd
auditpol /set /subcategory:"Process Creation" /success:enable

```
## 2️⃣ Expand Shell Detection

Attackers may use:
```cmd
cmd.exe
powershell.exe

```
Update query:
```spl
| search ProcName IN ("*cmd.exe", "*powershell.exe")

```

---
## 3️⃣ Verify Local Logs

Check locally:
```cmd
eventvwr.msc

```
Navigate:
```
Windows Logs → Security

```
Verify:
```
Event ID 4688

```
Exists.

---
## 🗺️ MITRE ATT&CK Mapping

|Technique	|ID	|Description |
|-----------|---|------------|
|Windows Management Instrumentation	|T1047	|Remote command execution |
|Command Execution	|T1059	|Shell execution |
|Lateral Movement	|TA0008	|Remote access |

---
## 🚩 Indicators of Compromise (IOCs)

Look for:

- ⚠️ wmiprvse.exe spawning cmd.exe
- ⚠️ Multiple cmd.exe launches
- ⚠️ Repeated execution patterns
- ⚠️ Unexpected administrative sessions

---
## 🛡️ Defensive Recommendations

Strengthen security posture:

- ✔️ Monitor parent-child process relationships
- ✔️ Alert on wmiprvse.exe spawning shells
- ✔️ Enable Sysmon logging
- ✔️ Restrict remote WMI access
- ✔️ Monitor privileged accounts

---
## 🧠 Key Takeaway

Multiple cmd.exe processes spawned by wmiprvse.exe is a strong indicator of an interactive WMI session.

This detection method provides:

- ✔️ High visibility
- ✔️ Reliable alerting
- ✔️ Strong lateral movement detection

---
## 🏁 Lab Conclusion

By analyzing:

- ✔️ Parent-child process relationships
- ✔️ Repeated shell execution patterns

We successfully identified interactive WMIExec activity, enabling defenders to detect lateral movement sessions in real-time.

---
## ✍️ Author

Abhay

🔐 Detection Engineering
🧠 Threat Hunting
📊 SIEM Engineering

---
