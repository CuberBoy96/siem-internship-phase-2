
# 🟣 Use Case 4 — Abnormal User Behavior Detection

![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-darkgreen)
![Tool](https://img.shields.io/badge/SIEM-Splunk-green)
![Use Case](https://img.shields.io/badge/Use%20Case-Abnormal%20User%20Behavior-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

# 🎯 Objective

Detect abnormal user login behavior occurring outside normal business hours.

This use case focuses on identifying:

- Successful logins during unusual hours  
- Valid credential misuse  
- Potential insider threat activity  
- Compromised account usage  

Such behavior often indicates unauthorized access using valid credentials.

---

# 🧱 Lab Setup

| Component | Description |
|----------|-------------|
| 🖥️ Attacker Machine | Kali Linux |
| 🪟 Victim Machine | Windows 10 |
| 📊 SIEM | Splunk Free Edition |
| 📡 Logging | Windows Security Logs |
| 🛠️ Tools Used | RDP, SMB Login |

---

# 🧪 Attack Simulation (Kali Side)

## Step 1 — Attempt Login During Off-Hours

Login to the Windows machine using valid credentials during abnormal hours (example: 2:00 AM).

From Kali:

```bash
xfreerdp /u:internuser /p:Password123 /v:192.168.1.10

```
This simulates unauthorized access using valid credentials.

---

## Step 2 — Perform Basic Activity

After login:

Run:
```cmd
whoami
hostname
dir

```
These simulate user activity after login.

---

## 🖥️ Victim Behavior (Windows Logs)

Windows generates:

|Event ID	|Description |
|---------|------------|
|4624	  |  Successful Login  |
|4634	  |  Logoff Event  |

Login Details Logged

Important fields:

Account Name
Login Time
Logon Type
Source IP

---

## 🔎 Splunk Detection Queries

Detect Logins Outside Business Hours
```spl
index=* EventCode=4624
| eval hour=strftime(_time,"%H")
| where hour<9 OR hour>19
| table _time Account_Name Source_Network_Address

```
Detect Late-Night Logins
```spl
index=* EventCode=4624
| eval login_time=strftime(_time,"%H:%M:%S")
| where login_time>"19:00:00" OR login_time<"09:00:00"
| table _time Account_Name login_time

```

---
## 📊 Detection Logic Explanation

This detection identifies:

- Successful login
- Login outside normal business hours
- Activity from valid account

Combined behavior indicates:

🚨 Abnormal User Behavior

---

## 🧠 MITRE ATT&CK Mapping

|Category	|Mapping  |
|---------|---------|
|🎯 Tactic	| Initial Access  |
|🧪 Technique	| T1078 — Valid Accounts  |


---
## ⚠️ False Positives

Possible legitimate causes:

- Night-shift employees
- IT maintenance tasks
- Scheduled automated logins

Validation steps:

- Verify user schedule
- Check maintenance logs
- Confirm authorized activity

🚨 Alert Severity

MEDIUM

Reason:

Off-hours login may indicate compromised credentials.

---

## 🔍 Investigation Playbook

SOC Analyst should:

- Identify login user
- Verify login time
- Check source IP address
- Confirm user schedule
- Review recent login activity
- Reset credentials if suspicious
- Monitor future logins

---

## 📁 Folder Structure
```
use-case-4-abnormal-user-behavior/
│
├── detection-logic/
|   ├── login-session/
|   ├── writeups.md
│   └── abnormal_login_detection.spl
|
├── screenshots/
│   ├── login-session.png
│   ├── command-execution.png
│   ├── splunk-query-result.png
│   └── alert-triggered.png
│
└── README.md

```

---

## 📸 Screenshot Checklist

Capture:

- ✅ Login session
- ✅ Command execution
- ✅ Windows login logs
- ✅ Splunk query results
- ✅ Alert triggered

---

## 📊 Expected Logs

You should see:

- EventCode=4624 → Successful Login  
- EventCode=4634 → Logoff Event  

---

## 🏁 Final Outcome

After completing:

- ✅ Off-hours login simulated
- ✅ Logs generated
- ✅ Detection query created
- ✅ Alert triggered

---
# :calendar: Year

**2026**

---

