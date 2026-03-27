
## 🟡 Use Case 2 — Single Combined Splunk Query
Lateral Movement Detection (All Steps in One Query)

This query detects:

- Failed Login Attempts
- Successful Remote Login
- Remote WMI Execution
- Remote PowerShell Execution

All inside one single search.

```spl
index=* (EventCode=4625 OR EventCode=4624 OR EventCode=4688)
| eval Activity=case
(
EventCode==4625,
"Failed Login Attempt",
EventCode==4624 AND LogonType=3,
"Successful Remote Login",
EventCode==4688 AND like(Creator_Process_Name,"%wmiprvse.exe%"),
"Remote Command Execution (WMI)",
EventCode==4688 AND like(New_Process_Name,"%powershell.exe%"),
"Remote PowerShell Execution"
)
| stats count
values(Activity) as Detected_Activities
values(Account_Name) as Users
values(Source_Network_Address) as Source_IP
values(New_Process_Name) as Processes
values(CommandLine) as Commands
by _time
| sort -_time

```

---

## 🎯 What This Query Detects (Full Use Case 2 Flow)

This single query covers your entire lateral movement attack chain.

Step	Attack Action	Event Detected
- Failed login	Event 4625
- Successful login	Event 4624
- Remote execution	wmiprvse.exe
- PowerShell execution	powershell.exe

---

So if attacker runs:
```bash
wmiexec.py internuser:Password123@192.168.1.10

```
This one query will detect the full activity chain.

---

## ⭐ SOC-Level Correlation Version (Recommended)

This version detects real lateral movement patterns.

```spl
index=* (EventCode=4625 OR EventCode=4624 OR EventCode=4688)
| eval Activity=case
(
EventCode==4625,"Failed Login",
EventCode==4624 AND LogonType=3,"Remote Login Success",
EventCode==4688 AND like(Creator_Process_Name,"%wmiprvse.exe%"),
"WMI Remote Execution",
EventCode==4688 AND like(New_Process_Name,"%powershell.exe%"),
"Remote PowerShell Execution"
)
| stats values(Activity) as Activities
values(Account_Name) as Users
values(Source_Network_Address) as Source_IP
values(CommandLine) as Commands
by Source_Network_Address
| where mvcount(Activities) >= 2

```

---

## 🚨 Best Alert Query for Use Case 2

Use this to create Splunk Alert.

```spl
index=* (EventCode=4625 OR EventCode=4624 OR EventCode=4688)
| stats count 
values(EventCode) as Events
by Source_Network_Address Account_Name
| where count >= 3

```

---

## 🧪 Real Attack Example

If attacker runs:
```bash
smbclient -L //192.168.1.10 -U internuser

```

Then:
```bash
wmiexec.py internuser:Password123@192.168.1.10

```

Then:
```cmd
powershell.exe
hostname
ipconfig

```

---

Splunk logs:

- 4625 → Failed Login
- 4624 → Successful Login
- 4688 → wmiprvse.exe
- 4688 → powershell.exe

Detected_Activities:

- Failed Login
- Remote Login Success
- WMI Remote Execution
- Remote PowerShell Execution

---

## 📊 Expected Output Example

|time                |Activities                 |
|--------------------|---------------------------|
|11:14:02            |Failed Login               |
|11:14:07            |Remote Login Success       |
|11:14:12            |WMI Remote Execution       |
|11:14:16            |Remote PowerShell Execution |

---

## ⭐ Real SOC Tip

If this query detects:

```
Failed Login
+
Successful Login
+
Remote Execution

```

---

## 🚨 HIGH CONFIDENCE LATERAL MOVEMENT

---
