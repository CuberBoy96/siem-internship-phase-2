# 🔍 SIEM Detection Lab — SIEM-internship-phase-2

![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-darkgreen)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-green)
![Focus](https://img.shields.io/badge/Focus-SOC%20Detection-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

# 📌 Project Overview

Welcome to the **SIEM Detection Lab Project**.

This repository demonstrates **real-world SOC detection engineering skills** through hands-on simulation of cyber attack techniques and detection using **Splunk SIEM**.

The goal of this project is to:

- Simulate attacker activity from **Kali Linux**
- Generate logs on **Windows systems**
- Ingest logs into **Splunk**
- Build detection queries
- Investigate suspicious activity
- Document detection engineering workflows

This project mirrors real **Security Operations Center (SOC)** workflows used in enterprise environments.

---

# 🎯 Project Objectives

✔ Build a functional SIEM lab  
✔ Simulate real attacker techniques  
✔ Collect Windows logs  
✔ Create Splunk detection rules  
✔ Perform threat analysis  
✔ Develop investigation workflows  
✔ Document professional SOC use cases  

---

# 🧱 Lab Architecture

            ┌─────────────────────┐
            │    Kali Linux VM    │
            │   (Attacker)        │
            └─────────┬───────────┘
                      │
                      │ Attacks
                      ▼
            ┌─────────────────────┐
            │   Windows 10 VM     │
            │   (Victim System)   │
            │ Sysmon Installed    │
            │ Splunk Forwarder    │
            └─────────┬───────────┘
                      │ Logs
                      ▼
            ┌─────────────────────┐
            │     Splunk SIEM     │
            │ (Detection Engine)  │
            └─────────────────────┘

---

# 🖥️ Lab Components

| Component | Purpose |
|----------|--------|
| 🐉 Kali Linux | Attack Simulation |
| 🪟 Windows 10 | Victim Machine |
| 📊 Splunk Free | Log Analysis |
| 📡 Splunk Universal Forwarder | Log Shipping |
| 🔍 Sysmon | Detailed Process Logging |

---

# 📊 Implemented Use Cases

This project includes **five SOC detection use cases** simulating common attacker techniques.

---

## 🔴 Use Case 1 — Privilege Escalation Attempt

Detect unauthorized privilege escalation through user creation and administrator privilege assignment.

### Techniques Simulated:

- Remote command execution  
- PowerShell usage  
- User account creation  
- Administrator privilege assignment  

📂 Folder:
    
    siem-detection-lab/
    │
    ├── use-case-1-privilege-escalation-attempt/

---

## 🟡 Use Case 2 — Lateral Movement

Detect remote execution and authentication across systems.

### Techniques Simulated:

- SMB authentication  
- Remote command execution  
- WMI-based execution  
- PowerShell lateral movement  

📂 Folder:

    siem-detection-lab/
    │
    ├── use-case-2-lateral-movement/

---

## 🔵 Use Case 3 — Suspicious File Download & Execution

Detect malicious file downloads and execution activity.

### Techniques Simulated:

- Remote file download  
- Malware execution  
- External network communication  

📂 Folder:

    siem-detection-lab/
    │
    ├── use-case-3-suspicious-file-download-execution/

---

## 🟣 Use Case 4 — Abnormal User Behavior

Detect suspicious login behavior outside normal working hours.

### Techniques Simulated:

- Off-hours login  
- Valid account misuse  

📂 Folder:

    siem-detection-lab/
    │
    ├── use-case-4-abnormal-user-behavior/

---

## 🔴 Use Case 5 — Command-and-Control (C2) Beaconing

Detect repeated outbound connections to attacker-controlled systems.

### Techniques Simulated:

- Beaconing communication  
- Repeated outbound network traffic  

📂 Folder:
      
    siem-detection-lab/
    │
    ├── use-case-5-c2-beaconing-behavior/

---

# 🧠 MITRE ATT&CK Coverage

| Use Case | Tactic | Technique |
|---------|--------|-----------|
| Privilege Escalation | Privilege Escalation | T1068, T1098 |
| Lateral Movement | Lateral Movement | T1021, T1047 |
| File Execution | Execution | T1204, T1105 |
| Abnormal Login | Initial Access | T1078 |
| C2 Beaconing | Command & Control | T1071 |

---

# 📁 Repository Structure

    siem-detection-lab/
    │
    ├── use-case-1-privilege-escalation-attempt/
    │ ├── screenshots/
    │ ├── detection-logic/
    │ ├── writeups/
    │ └── README.md
    │
    ├── use-case-2-lateral-movement/
    │ ├── screenshots/
    │ ├── detection-logic/
    │ ├── writeups/
    │ └── README.md
    │
    ├── use-case-3-suspicious-file-download-execution/
    │
    ├── use-case-4-abnormal-user-behavior/
    │
    ├── use-case-5-c2-beaconing-behavior/
    │
    └── README.md

---

# 🔎 Detection Engineering Workflow

Each use case follows this workflow:

1️⃣ Simulate attack from Kali  
2️⃣ Generate logs on Windows  
3️⃣ Forward logs to Splunk  
4️⃣ Build SPL detection query  
5️⃣ Validate detection  
6️⃣ Investigate activity  
7️⃣ Document results  

This replicates a **real SOC workflow**.

---

# 📸 Screenshots Included

Each use case includes:

✅ Attack execution  
✅ Windows logs  
✅ Sysmon events  
✅ Splunk query output  
✅ Alert trigger  

These provide **visual verification** of detection logic.

---

# 🧪 Tools Used

| Tool | Purpose |
|------|--------|
| Splunk | SIEM Platform |
| Sysmon | Process Monitoring |
| Kali Linux | Attack Simulation |
| wmiexec.py | Remote Execution |
| smbclient | SMB Access |
| PowerShell | Windows Execution |
| Netcat | Network Simulation |

---

# 🚨 Detection Capabilities Demonstrated

This project demonstrates:

✔ Privilege Escalation Detection  
✔ Lateral Movement Detection  
✔ Malware Execution Detection  
✔ Suspicious Login Detection  
✔ C2 Communication Detection  

These represent **core SOC detection scenarios**.

---

# 📈 Skills Demonstrated

This project showcases:

- SIEM Deployment  
- Log Analysis  
- Detection Engineering  
- Threat Hunting  
- Incident Investigation  
- MITRE ATT&CK Mapping  
- Security Documentation  

These are **core SOC analyst skills**.

---

# 🔍 Future Improvements

Planned enhancements:

- Splunk Dashboards  
- Correlation Searches  
- Alert Automation  
- Threat Intelligence Integration  
- MITRE ATT&CK Dashboard  

---

# ⭐ Project Outcome

After completing this project:

✅ Built full SIEM lab  
✅ Simulated real-world attacks  
✅ Created detection logic  
✅ Investigated threats  
✅ Documented SOC workflows  

This project demonstrates **practical SOC detection engineering experience**.

---

# 👨‍💻 Author

**Abhaykant Vishwakarma**

🔐 SOC Analyst Enthusiast  
🛡️ Cybersecurity Learner  
📊 SIEM & Threat Detection  

# 📅 Year

**2026**

---
