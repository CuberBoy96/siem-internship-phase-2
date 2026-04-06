# 🛡️ Detection Engineering Lab: Unauthorized Admin Group Addition

![MITRE](https://img.shields.io/badge/MITRE-T1098-red)
![Technique](https://img.shields.io/badge/Technique-Privilege%20Escalation-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-orange)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![Status](https://img.shields.io/badge/Detection-Working-success)

---

# 📌 Project Overview

This lab focuses on detecting **Privilege Escalation** through the unauthorized addition of users to the **local Administrators group**.

Attackers often elevate privileges by adding their accounts to privileged groups, allowing them to:

- Gain administrative access
- Maintain persistence
- Disable security controls
- Move laterally across systems

This project bridges the gap between:

- ⚔️ **Attacker Activity**  
- 🛡️ **Defender Visibility in Splunk**

---

# 🧪 Lab Architecture
```
Kali Linux (Attacker)
│
│ Impacket-PSExec
▼
Windows Target System
│
│ Local Group Modification
▼
Windows Security Logs
│
▼
Splunk SIEM
│
▼
Privilege Escalation Detection 🚨

```

---
## ⚔️ Phase 1: Attack Simulation

In this scenario, an attacker who has already gained initial access performs **privilege escalation** by adding a controlled user to the **local Administrators group**.

Tool Used:


Impacket-PSExec


---

## 💻 Attack Command

Executed from the Kali Linux attacker machine:

```bash
# Adding 'Newuser1' to the local Administrators group
impacket-psexec abhay:CB@i510400f@10.193.10.80 "net localgroup administrators Newuser1 /add"

```
## ✅ Result

- ✔️ User Newuser1 gained Administrator privileges

---
## 📊 Phase 2: Detection Visibility

This attack generates:

|Event Type	|Event ID	|Description |
|-----------|---------|------------|
|Process Creation	|4688 / 1	|Command execution |
|Group Membership Change	|4732	|User added to local group |

Event 4732 is the primary detection signal.

---
## 🛠️ Phase 3: Troubleshooting Visibility "Blockers"

If your Splunk dashboard is empty, check these:

## 1️⃣ Verify Local Logs

Open:
```cmd
eventvwr.msc

```
Navigate:
```
Windows Logs → Security

```
Filter for:

- Event ID 4688
- Event ID 4732

---
## 2️⃣ Enable Audit Policy

Windows does not always log these events by default.

Run on Windows:

Enable Process Creation Logging
```cmd
auditpol /set /subcategory:"Process Creation" /success:enable
```
Enable Account Management Logging
```cmd
auditpol /set /subcategory:"User Account Management" /success:enable
```

---
## 3️⃣ Verify Sysmon Installation (Optional)

If using Sysmon:

Check service:
```
sc query sysmon
```
---
Ensure:

- ✔️ Sysmon is running
- ✔️ EventCode 1 logs exist

---
## 🧩 Phase 4: Field Normalization (Decoder Ring)

Different log sources use different field names.
```spl
Use coalesce() to normalize them.

```

---
## 🔄 Field Normalization Mapping

|Information	|Raw Field	|Normalized Field |
|-------------|-----------|-----------------|
|Process Name	|New_Process_Name	|Process  |
|Parent Process	|Creator_Process_Name	|Parent  |
|User Account	|Account_Name	|User  |

---
## 🏆 Phase 5: High-Fidelity Detection (Splunk)

This is the core detection logic.

## 🔍 Detection Query 1 — Event ID 4732

Detect when a user is added to a local group.
```spl
index=* EventCode=4732

| rename MemberName as TargetUserName,
         Account_Name as SubjectUserName

| table _time,
        SubjectUserName,
        TargetUserName

```

---
## 💎 Detection Query 2 — Universal ("Greedy") Version

Handles inconsistent field naming.
```spl
index=* EventCode=4732

| eval User = coalesce(src_user, user, Account_Name)

| table _time,
        User,
        TargetUserName

```

---
## 🧠 Phase 6: Multi-Layer Detection Strategy

To strengthen detection:

Monitor:
```
net localgroup administrators /add

```
Alongside:
```
Event ID 4732

```
This creates:

- 🛡️ Defense-in-Depth

---
## 🗺️ MITRE ATT&CK Mapping

|Technique	|ID	 |Description |
|-----------|----|------------|
|Account Manipulation	|T1098	|Modify account privileges |
|Privilege Escalation	|TA0004	|Gain elevated permissions |
|Persistence	|TA0003	|Maintain access |

---
## 🚩 Indicators of Compromise (IOCs)

Look for:

- ⚠️ net localgroup administrators
- ⚠️ Event ID 4732
- ⚠️ Unknown user gaining admin rights
- ⚠️ Rapid privilege escalation activity

---
## 🛡️ Defensive Recommendations

Improve detection posture:

- ✔️ Monitor Event ID 4732
- ✔️ Alert on Admin group changes
- ✔️ Restrict PSExec usage
- ✔️ Monitor privileged actions
- ✔️ Review administrative logs regularly

---
## 🧠 Key Takeaway

Monitoring Event ID 4732 provides a reliable detection mechanism for unauthorized privilege escalation.

Combining:

- ✔️ Process Monitoring
- ✔️ Group Change Monitoring

Creates strong defensive visibility.

---
## 🏁 Lab Conclusion

By combining:
```
Process Creation Monitoring (4688 / 1)
Group Membership Monitoring (4732)

```
We created a multi-layer detection strategy capable of identifying privilege escalation attempts.

This significantly strengthens enterprise security visibility.

---
## ✍️ Author

Abhay

🔐 Detection Engineering
🧠 Threat Hunting
📊 SIEM Engineering

---
