# siem-internship-phase-2

Welcome to the **SIEM Internship Phase-2** repository. 
This Phase shifts focus from basic detection to simulating and detecting attacker behavior after gaining access to a system.

In this Phase, we will simulate and detect post-compromise activities that a real attacker might perform after gaining initial access. Focus areas include persistence, lateral movement, privilege escalation, and anomalous behavior detection.

---

## 🎓 Internship Objective

* Detect advanced attacker behavior post-compromise.
* Simulate realistic threat actor techniques (pivilege escalation, lateral movement, persistence, file downloads)
* Improve event correlation, rule building, and incident reporting skills.

---

## 📚 Lab Architecture

* **Host Machine**: Running Splunk Web Interface
* **Windows 10 VM**: Target machine with Sysmon, Event Logs, and Splunk Universal Forwarder
* **Kali Linux VM**: Used for attack simulation using tools like `hydra` and `crackmapexec`

Logs from the Windows VM are shipped to the host Splunk instance using Splunk Universal Forwarder.

---

## 📊 Use Cases Implemented

### 1. Privilege Escalation

* **Technique**: Gaining higher-level access rights through account creation and privilage escalation.
* **Event IDs**: 4720 (Account created), 4728 (Account with admin privilage), 4672 (Failed to add user to group), 4732 (User added to group successfull)
* **Tools**: crackmapexec (Kali), Windows Security Logs
* **Goal**: Gaining Higher-level access rights for privileged account from the same IP.

### 2. Lateral Movement

* **Technique**: Moving across systems in the network.
* **Event ID**: 4624 (Logontype 3/10) & Sysmon Event ID 3 (network concept)
* **Tools**: PSExec, Powershell(windows) 
* **Logic**: Alert on remote execution from user IP or An non-standard admin tool usage will trigger an alert.

### 3. C2 Communication

* **Technique**: C2 Beaconing Detection
* **Event ID**: Sysmon Event ID 3 (outbound HTTP)
* **Goal**: Detect repetitive calls to same rare domain

### 4. Suspicious File Activity

* **Technique**: Suspicious File Download and Execution 
* **Event IDs**: Sysmon 1 (Process Execution), Parent: powershell.exe
* **Goal**: Detect files like .exe, .ps1 in Downlaods folder.

### 5. User Behavior Analytics

* **Technique**: Anomalous User Behavior
* **Event IDs**: 4624 (login), 5140/4663 (file access)
* **Goal**: Detect or analysis Logon Pattern :(Login during midnight), Access file drive share :(map drive, copy 50+ files)

---

## 🗃️ Folder Structure

```
siem-internship-phase-2/
├── use-case-1-privilege-escalation-attempt/
│   ├── detection-logic/
│   ├── screenshots/
│   └── writeups/
├── use-case-2-lateral-movement/
├── use-case-3-suspicious-file-downlaod-&-execution/
├── use-case-4-adnormal-user-behavior/
├── use-case-5-C2-beaconing-behavior/
└── README.md
```

Each folder contains:

* `screenshots/`: Attack simulation, log entries, query results, and alerts
* `detection-logic/`: Detection queries used in Splunk (SPL)
* `writeups/`: Scenario explanation, objective, tools used, detection mapping

---

## 🌍 Tools Used

* **SIEM**: Splunk Free
* **Monitoring Tools**: Sysmon, Event Viewer
* **Attack Tools**: PSExec, PowerShell, net user 
* **Forwarder**: Splunk Universal Forwarder for log shipping

---

## 📄 Submission Checklist

* [x] Screenshots of each detection scenario
* [x] SPL queries for alert logic
* [x] Markdown writeups per use case
* [x] Logs demonstrating detection in Splunk

---

## 🚀 Outcome

By completing this project, I learned:

* Correlate events across multiple systems.
* Detect and investigate attacker behavior post-login. 
* Build and document detection logic using real data.
* Improve SIEM rule tunning and false positive analysis.

---

## 🌟 Special Thanks

To the mentors and community resources that helped along the way — and to the open-source community whose tools made this project possible.

---

Feel free to explore each use case folder to see queries, screenshots, and documentation of the detection logic.

---

📆 2025
