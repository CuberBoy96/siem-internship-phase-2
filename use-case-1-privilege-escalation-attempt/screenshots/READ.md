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
