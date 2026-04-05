# 🔴 Use Case 1 — Privilege Escalation Attempt Detection

![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-darkgreen)
![Tool](https://img.shields.io/badge/SIEM-Splunk-green)
![Use Case](https://img.shields.io/badge/Use%20Case-Privilege%20Escalation-red)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

# 🎯 Objective

Detect privilege escalation attempts where an attacker creates new user accounts and assigns administrative privileges.

This use case focuses on identifying:

- Remote command execution  
- PowerShell execution  
- User account creation  
- Addition of user to Administrators group  

These behaviors indicate unauthorized privilege escalation activity.

---

# 🧱 Lab Setup

| Component | Description |
|----------|-------------|
| 🖥️ Attacker Machine | Kali Linux |
| 🪟 Victim Machine | Windows 10 |
| 📊 SIEM | Splunk Free Edition |
| 📡 Logging | Windows Security Logs + Sysmon |
| 🛠️ Tools Used | wmiexec.py (Impacket), PowerShell |

---

# 🧪 Attack Simulation (Kali Side)

## Step 1 — Remote Command Execution

From Kali:

```bash
wmiexec.py username:password@192.168.1.10

```
## Step 2 — Launch Command Prompt

```cmd
cmd.exe

```
Step 3 — Execute Powershell

```cmd
powershell.exe

```
## Step 4 — Create New User Account

```cmd
net user ironman p@ssw0rd /add

```
### Step 5 — Add user to Administrators Group

```cmd
net localgroup administrators ironman /add

```

---

## 🖥️ Victim Behavior (Windows Logs)

| Source       | Event ID / Field | Description                |
| ------------ | ---------------- | -------------------------- |
| Windows Logs | 4688             | Process created       |
| Windows Logs | 4720             | User Created    |
| Windows Logs | 4732             | User Added to Administrators group  |
| Windows Logs | 4672             | Special Privileges Assigned |
| Sysmon       | Event ID 1       | Process Execution |

---

## Parent-child process example:

```
wmiprvse.exe → cmd.exe  
cmd.exe → powershell.exe  
powershell.exe → net.exe  

```
This strongly indicates remote privilege escalation behavior.

---

## 🔎 Splunk Detection Queries

Detect Remote Process Execution

```spl
index=* EventCode=4688
Creator_Process_Name="*wmiprvse.exe"
| table _time New_Process_Name Account_Name

```

Detect PowerShell Execution

```spl
index=* EventCode=4688
New_Process_Name="*powershell.exe"
| table _time Account_Name Creator_Process_Name

```

Detect User Account Creation

```spl
index=* EventCode=4720
| table _time SubjectUserName TargetUserName

```

Detect Admin Group Assignment

```spl
index=* EventCode=4732
TargetUserName="Administrators"
| table _time MemberName SubjectUserName

```

Detect Privileged Token Assignment

```spl
index=* EventCode=4672
| table _time Account_Name Privileges

```

## 📊 Detection Logic Explanation

This detection identifies:

- Remote execution using WMI
- PowerShell execution
- Creation of a new user
- Addition to Administrators group

When these activities occur together, it strongly indicates:

🚨 Privilege Escalation Attempt

---

## 🧠 MITRE ATT&CK Mapping

|Category	|Mapping    |
|-----------|-----------|
|🎯 Tactic	|Privilege Escalation    |
|🧪 Technique	|T1068 — Exploitation for Privilege Escalation   |
|🧪 Technique	|T1098 — Account Manipulation   |

---

## ⚠️ False Positives

Possible legitimate causes:

- IT administrators creating accounts
- Software installation requiring admin access
- Automated deployment scripts

Validation Steps:

- Verify administrator identity
- Confirm authorized change request
- Review maintenance schedules

---

## 🚨 Alert Severity

CRITICAL

Reason:

Administrative privilege assignment is considered high-risk behavior.

---

## 🔍 Investigation Steps

SOC Analyst should:

- Identify newly created account
- Verify legitimacy of user
- Review command history
- Identify source IP
- Disable suspicious account
- Reset affected credentials
- Monitor for additional activity

---
## 📁 Folder Structure
    use-case-1-privilege-escalation-attempt/
    │
    ├── detection-logic/
    |   ├── wmiexec-session/     
    |   |   ├── screenshots/
    |   │   ├── wmiexec-session.png
    |   │   ├── powershell-execution.png
    |   │   ├── account-created.png
    |   │   ├── splunk-query-result.png
    |   │   └── alert-triggered.png
    |   |
    |   ├── writeups.md
    │   └── privilege_escalation_detection.spl
    │
    └── README.md

---

## 📸 Screenshot Checklist

Capture:

- ✅ Remote command execution
- ✅ PowerShell execution
- ✅ User creation logs
- ✅ Admin group assignment
- ✅ Splunk detection output
- ✅ Alert triggered

---

## 🧪 Testing Validation

Verify:

- User account created successfully
- User added to Administrators group
- Logs appear in Splunk
- Detection query works
- Alert triggers correctly

---

## 📊 Expected Logs

You should observe:

- EventCode=4688 → Process Created  
- EventCode=4720 → User Created  
- EventCode=4732 → Admin Group Assignment  
- EventCode=4672 → Privilege Assignment  
- Sysmon Event 1 → Process Execution  

---

## 🏁 Final Outcome

After completing this use case:

- ✅ Privilege escalation simulated
- ✅ Windows logs generated
- ✅ Logs forwarded to Splunk
- ✅ Detection query created
- ✅ Alert triggered successfully

---

# 📅 Year

**2026**

---

