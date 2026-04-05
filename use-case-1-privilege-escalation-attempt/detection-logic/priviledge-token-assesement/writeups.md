# 🛡️ Detection Engineering Lab: Tracking Lateral Movement & Privilege Escalation

This guide is your "Liquid Gold" playbook for mastering Windows forensics in Splunk. We move from simulating advanced attacks to crafting high-fidelity detection queries that catch attackers in the act.

---

## ⚔️ Phase 1: The Attack Surface (Simulation)

To catch a thief, you must think like one. In this lab, we simulated two primary methods of lateral movement and privilege escalation using the **Impacket** suite.

### 1. Remote Command Execution (WMIExec)
We used `wmiexec` to execute commands remotely. This is stealthy because it leverages the built-in WMI service.
* **Command:** `impacket-wmiexec abhay:CB@i510400f@10.193.10.80 "powershell.exe -Command whoami"`
* **Result:** Logged in as `desktop-k7ml152\abhay`.

### 2. Privilege Escalation (PSExec)
We used `psexec` to gain the highest level of access on the target system.
* **Command:** `impacket-psexec abhay:CB@i510400f@10.193.10.80`
* **Result:** Escalated to **`nt authority\system`**.

---

## 📂 Phase 2: The Data Challenge (Field Normalization)

The biggest "blocker" for SOC analysts is that different log sources (Windows Security vs. Sysmon) use different names for the same data. If your query isn't normalized, you are blind.

| ✨ Information | 📂 Windows 4688 Field | 📊 Sysmon 1 Field | 💎 The "Universal" Alias |
| :--- | :--- | :--- | :--- |
| **Process Name** | `New_Process_Name` | `Image` | `ProcName` |
| **Parent Process** | `Creator_Process_Name` | `ParentImage` | `Parent` |
| **User Account** | `Account_Name` | `TargetUserName` | `User` |

---

## 🏆 Phase 3: The "Universal" Detection Query (Liquid Gold)

This query uses the `coalesce` function to bridge the gap between log sources. It specifically hunts for the **WMI Lateral Movement signature**: `wmiprvse.exe` spawning a shell.

```splunk
index=* (EventCode=4688 OR EventCode=1)
| eval Parent = coalesce(Creator_Process_Name, ParentImage, ParentProcessName)
| eval Child  = coalesce(New_Process_Name, Image, NewProcessName)
| eval User   = coalesce(Account_Name, user, TargetUserName)
| search Parent="*wmiprvse.exe*"
| table _time, User, Parent, Child
| sort - _time

```

---
## 💎 Phase 4: Hunting for Privilege Escalation (Event 4672)
When an attacker successfully escalates privileges (like our PSExec attack), Windows generates Event ID 4672 (Special Logon / Privileged Token Assignment). This is a critical alert for any SOC.

---
## 🔍 Detection Query:
```spl
snippetindex=* EventCode=4672 Account_Name!="SYSTEM"
| table _time, Account_Name, Privileges

```
What to look for: Accounts like abhay assigned high-level privileges like SeSecurityPrivilege or SeBackupPrivilege unexpectedly.

---
## 🛠️ Phase 5: Ground Truth & Troubleshooting:
If your Splunk dashboard is blank, follow this Emergency Checklist:
1. Verify Local LogsOpen
Event Viewer (eventvwr.msc) on the target machine and check Windows Logs > Security. If you don't see Event ID 4688, the logs aren't being generated.
2. Force Audit Policy
Windows does not log process creations by default. Fix this by running this in an Admin
```cmd
DOSauditpol /set /subcategory:"Process Creation" /success:enable

```
3. Check SysmonEnsure the Sysmon service is installed and running if you are relying on EventCode 1

---
## 🏁 Summary of Findings
|GoalEvent |CodeKey |Indicator       |
|----------|--------|----------------|
|Detect WMIExec   |4688/1 | wmiprvse.exe → cmd.exe/powershell.exe |
|Detect Privilege Escalation |4672 | Unusual user assigned SeSecurityPrivilege |
|Detect PSExec | 1 |Creation of a randomized service binary (e.g., ahqyclNm.exe) |

---
## ✍️ Author: 

Abhay

---
