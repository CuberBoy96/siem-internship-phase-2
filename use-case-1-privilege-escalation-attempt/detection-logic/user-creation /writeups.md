# 🛡️ Detection Engineering Lab: Unauthorized User Creation & Persistence

![MITRE](https://img.shields.io/badge/MITRE-T1136-red)
![Technique](https://img.shields.io/badge/Technique-User%20Creation-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![Status](https://img.shields.io/badge/Detection-Working-success)

---

# 📌 Project Overview

In this lab, we simulated a **common persistence technique** where an attacker creates a **new local user account** on a compromised Windows system.

Attackers often create hidden or unauthorized accounts to maintain **persistent access**, even if the original vulnerability is patched.

This lab demonstrates how to:

- Simulate unauthorized user creation
- Normalize inconsistent logs
- Detect suspicious activity in **Splunk**
- Validate detection using **Windows Event Logs**

---

# 🧪 Lab Architecture
```
Kali Linux (Attacker)
│
│ Impacket-PSExec
▼
Windows Target System
│
│ Process & Account Logs
▼
Splunk SIEM
│
▼
Detection Alert 🚨

```

---

---

# ⚔️ Phase 1: Attack Simulation

Attackers create new accounts to maintain persistence.

We simulated this using:
```
Impacket-PSExec

```
---

# 💻 Attack Method 1 — Standard Command Line

Command executed from Kali Linux:

```bash
impacket-psexec abhay:CB@i510400f@10.193.10.80 "net user Newuser1 Password123 /add"

```

---
## ✅ Result

✔️ Successfully created a new local user:
```
Newuser1

```

---
## 💻 Attack Method 2 — PowerShell User Creation

Alternative PowerShell method:
```bash
impacket-psexec abhay:CB@i510400f@10.193.10.80 "powershell.exe -Command New-LocalUser -Name 'Ghostadmin' -NoPassword"

```

---
## ⚠️ Important Note

Even if the PowerShell command fails:

- ✔️ Logs are still generated
- ✔️ Detection remains possible

---
## 📂 Phase 2: The Data Normalization Challenge

Different log sources use different field names.

To create reliable detection rules, we normalize field names.

🧩 Field Normalization Mapping 
|✨ Information	|📂 Windows 4688	|📊 Sysmon Event 1	|💎 Universal Alias |
|---------------|-----------------|-------------------|---------------------|
|Process Name	|New_Process_Name	|Image	|ProcName |
|Parent Process	|Creator_Process_Name	|ParentImage	|Parent  |
|User Account	|Account_Name	|user / TargetUserName	|User  |

---
## 🏆 Phase 3: Detection Strategy (Splunk)

We created two detection layers:

- 1️⃣ Process-Level Detection
- 2️⃣ Account Creation Event Detection

---
## 🔍 Detection Layer 1: Process-Level Detection

Detect execution of:
```
net.exe user
powershell.exe

```

---
## 🧪 Universal Hunter Query
```spl
index=* (EventCode=4688 OR EventCode=1)

| eval Parent = coalesce(Creator_Process_Name, ParentImage, ParentProcessName)

| eval Child  = coalesce(New_Process_Name, Image, NewProcessName)

| eval User   = coalesce(Account_Name, user, TargetUserName)

| search Child="*net.exe*" AND Child="*user*"

| table _time, User, Parent, Child

| sort - _time

```

---
## 🔐 Detection Layer 2: Account Management Detection

Windows generates:
```
Event ID 4720
```
Whenever:

✔️ A new user account is created.

---
## 🧪 High-Fidelity Detection Query
```spl
index=* EventCode=4720

```

---
## 📊 Detection Result

Splunk detected:
```
Newuser1
```
Created at:
```
13:17:39
```

---
## 🛠️ Phase 4: Troubleshooting Empty Results

If detection fails, check these:

## 1️⃣ Enable Audit Policy

User Account Management logging is often disabled.

Run this command:
```cmd
auditpol /set /subcategory:"User Account Management" /success:enable

```

---
## 2️⃣ Local Verification

Check logs locally:
```cmd
eventvwr.msc

```
Verify:
```
Event ID 4720
```
Exists before blaming Splunk.

---
## 3️⃣ Permission Issues

If command fails:
```
Access Denied
```
Then:

- ❌ No logs generated
- ✔️ Use Administrator privileges

---
## 🗺️ MITRE ATT&CK Mapping
|Technique	|ID	 |Description  |
|-----------|----|-------------|
|Create Account	|T1136	|Create new local user |
|Valid Accounts	|T1078	|Maintain access using credentials |
|Persistence	|TA0003	\Maintain long-term access |

---
## 🚩 Indicators of Compromise (IOCs)

Look for:

- ⚠️ net.exe user /add
- ⚠️ powershell.exe New-LocalUser
- ⚠️ Event ID 4720
- ⚠️ Unknown user accounts

---
## 🛡️ Defensive Recommendations

Improve security posture:

- ✔️ Enable Account Management Auditing
- ✔️ Monitor Event ID 4720
- ✔️ Alert on new local users
- ✔️ Restrict PSExec usage
- ✔️ Review privileged actions

---
## 🧠 Key Takeaway

Monitoring Event ID 4720 together with suspicious net.exe user activity provides a strong detection mechanism against unauthorized persistence.

---
## 🏁 Lab Conclusion

By combining:

- ✔️ Process Monitoring
- ✔️ Account Management Events

We created a robust detection workflow capable of identifying unauthorized user persistence attempts.

This approach significantly improves visibility into attacker behavior.

---
## ✍️ Author

Abhay

🔐 Detection Engineering
🧠 Threat Hunting
📊 SIEM Engineering

---
