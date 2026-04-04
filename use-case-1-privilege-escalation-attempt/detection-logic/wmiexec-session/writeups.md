# 🛡️ Remote Process Execution Detection via WMI (wmiexec) — Splunk Use Case

![MITRE](https://img.shields.io/badge/MITRE-T1047-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![Status](https://img.shields.io/badge/Status-Detection%20Working-success)

---

# 📌 Overview

This project demonstrates detection of **remote process execution via WMI** using **Impacket wmiexec** and monitoring Windows logs in **Splunk**.

## 🎯 **Goal:**  
Simulate an attacker executing commands remotely and detect the activity using **process creation logs**.

---

# 🧪 Lab Architecture
```
Kali Linux (Attacker)
│
│ wmiexec (WMI)
▼
Windows Target
│
│ Process Creation Logs
▼
Splunk SIEM
│
▼
Detection Alert 🚨

```
---

# ⚙️ Lab Setup

## 🖥️ Attacker Machine

- OS: **Kali Linux**
- Tool Used: **Impacket wmiexec**
- Purpose: Remote command execution

---

## 🎯 Target Machine

- OS: **Windows**
- Logging Enabled:

| Log Source | Event Code | Description |
|-------------|-------------|-------------|
| 🧠 Sysmon | 1 | Process Creation |
| 🔐 Security Log | 4688 | Process Creation |

---

## 📊 SIEM Platform

- **Splunk**

Used to:

- Collect logs  
- Run detection queries  
- Investigate process activity  

---

# 🚨 Attack Simulation

Remote command execution performed using:

```bash
impacket-wmiexec abhav:CB@i510400fa@10.193.10.80 whoami

```

---

## ✅ Execution Result
```
[*] SMBv3.0 dialect used
desktop-k7ml152\abhay

```
✔️ Successful remote execution confirmed

---
## 🎯 Detection Objective

Detect remote execution where:

```
Parent Process 👇
wmiprvse.exe
Child Process 👇
cmd.exe

```
---
## 🧠 Why This Works

When wmiexec runs commands remotely:
```
wmiprvse.exe → cmd.exe

```

---
This process chain strongly indicates:

- 🛰️ Remote command execution
- 🔄 Lateral movement
- 🧨 Potential attacker activity
- ⚠️ Common Detection Issues

---
If logs are missing in Splunk, check these:

## 1️⃣ Field Name Mismatch (Most Common)

Different logs use different fields.

Parent Process Fields
|Event Type	      |Field Name |
|-----------------|-----------|
|🧠 Sysmon	       |ParentImage  |
|🔐 Security Log	 |ParentProcessName  |

---
Child Process Fields
|Event Type	|Field Name |
|-----------|-----------|
|Sysmon	     |Image  |
|Security Log	 |NewProcessName  |

---
## 2️⃣ Enable Process Creation Auditing

Windows does NOT log process creation by default.

Run this on Windows:

auditpol /set /subcategory:"Process Creation" /success:enable
3️⃣ Incorrect Process Field Usage

Sysmon mapping:

Image = New Process
ParentImage = Parent Process
🧩 Universal Detection Query (Recommended)

Works for:

Sysmon
Windows Security Logs
index=* (EventCode=4688 OR EventCode=1)

| eval Parent = coalesce(Creator_Process_Name, ParentImage, ParentProcessName)

| eval Child = coalesce(New_Process_Name, Image, NewProcessName)

| eval User = coalesce(Account_Name, user, TargetUserName)

| search Parent="*wmiprvse.exe*"

| table _time User Parent Child
🧪 Working Detection Query (Lab Verified)
index=* (EventCode=4688 OR EventCode=1)
Creator_Process_Name="*wmiprvse.exe*"
| table _time New_Process_Name Account_Name
📊 Detection Results

Splunk detected:

3 Process Creation Events

🧾 Observed Events
⏰ Time	🧠 Process	👤 User
12:33:42	C:\Windows\System32\cmd.exe	DESKTOP-K7ML152$\abhay
12:33:42	C:\Windows\System32\cmd.exe	DESKTOP-K7ML152$\abhay
12:33:42	C:\Windows\System32\cmd.exe	DESKTOP-K7ML152$\abhay

✔️ Detection Successful

🔬 Detection Logic Breakdown
Suspicious Parent Process
wmiprvse.exe

This is:

🧠 WMI Provider Host

Used by:

Remote WMI execution
Lateral movement
Malware operations
Suspicious Child Processes

Watch for:

cmd.exe
powershell.exe
wscript.exe

These indicate:

⚠️ Command execution activity.

🗺️ MITRE ATT&CK Mapping
Technique	ID
Windows Management Instrumentation	🎯 T1047
Remote Services	🎯 T1021
Command Execution	🎯 T1059
🚩 Indicators of Compromise (IOCs)

Look for:

Parent Process
wmiprvse.exe
Child Processes
cmd.exe
powershell.exe
wscript.exe
Suspicious Behaviors
🔁 Rapid process launches
🌐 Remote execution
🧑‍💻 Privileged account usage
🕒 Odd execution times
🔧 Detection Improvements

Enhance detection accuracy:

Monitor More Child Processes
| search Child IN ("cmd.exe","powershell.exe","wscript.exe")
Detect Remote PowerShell
| search Child="*powershell.exe*"
Add Host Tracking
| table _time host User Parent Child
🕵️ Threat Hunting Tips

Look for:

wmiprvse spawning shells
Execution at unusual times
Multiple affected hosts
Repeated command execution
🛡️ Defensive Recommendations

Improve detection posture:

✅ Enable Sysmon logging
✅ Enable Process Creation auditing
✅ Restrict WMI remote access
✅ Monitor privileged accounts
✅ Deploy EDR rules
🖼️ Screenshots Included

📸 This project contains:

wmiexec execution proof
Splunk detection logs
Universal detection query
Troubleshooting workflow
🧾 Detection Summary
Field	Value
🎯 Detection Type	Remote Execution
🧠 Parent Process	wmiprvse.exe
⚙️ Tool Simulated	wmiexec
📊 SIEM	Splunk
🛡️ Status	Successful Detection
🎉 Conclusion

This lab demonstrates how attackers can execute commands remotely using WMI, and how defenders can successfully detect this activity using Splunk process logs.

🔑 Key Takeaway

Monitoring wmiprvse.exe spawning shell processes is a powerful method to detect WMI-based remote execution attacks.

👨‍💻 Author

Abhay

🔐 Detection Engineering
🧠 Threat Hunting
📊 SIEM Engineering
