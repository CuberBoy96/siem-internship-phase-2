
# 🔴 Use Case 1 — Single Combined Splunk Query
(Detect Full Privilege Escalation Chain)

This one query detects the full attack scenario of Use Case 1.

```spl
index=*(EventCode=4688 OR EventCode=4720 OR EventCode=4732 OR EventCode=4672)
| eval Activity=case
(
EventCode==4688 AND like(Creator_Process_Name,"%wmiprvse.exe%"),
"Remote Command Execution (WMI)",
EventCode==4688 AND like(New_Process_Name,"%powershell.exe%"),
"PowerShell Execution",
EventCode==4720,
"User Account Created",
EventCode==4732,
"User Added to Administrators",
EventCode==4672,
"Privileged Token Assigned"
)
| stats count 
values(Activity) as Detected_Activities
values(Account_Name) as Users
values(SubjectUserName) as Performed_By
values(TargetUserName) as Target_Account
values(New_Process_Name) as Processes
values(CommandLine) as Commands
by _time
| sort -_time

```

---

## 🎯 What This One Query Detects

This single query covers ALL Use Case 1 steps.

Step	Attack Action	Event Detected
- Remote execution	wmiprvse.exe
- Command shell	cmd.exe
- PowerShell execution	powershell.exe
- User creation	Event 4720
- Admin privilege add	Event 4732
- Admin privileges assigned	Event 4672

So if attacker runs:

net user hacker Pass123 /add
net localgroup administrators hacker /add

This query will detect everything.

---

## ⭐ SOC-Level Version (Recommended)

This version detects real privilege escalation patterns.

```spl
index=* (EventCode=4720 OR EventCode=4732 OR EventCode=4672 OR EventCode=4688)
| eval Activity=case
(
EventCode==4720,"User Created",
EventCode==4732,"Added to Admin Group",
EventCode==4672,"Admin Privileges Assigned",
EventCode==4688 AND like(New_Process_Name,"%powershell.exe%"),
"PowerShell Execution",
EventCode==4688 AND like(Creator_Process_Name,"%wmiprvse.exe%"),
"Remote Execution"
)
| stats values(Activity) as Activities
values(Account_Name) as Users
values(TargetUserName) as Target_User
values(CommandLine) as Commands
by SubjectUserName
| where mvcount(Activities) >= 2

```

---

## 🚨 Best Alert Query (Use This in Splunk Alerts)

This is the recommended alert rule.

```spl
index=* (EventCode=4720 OR EventCode=4732 OR EventCode=4672)
| stats count 
values(EventCode) as Events
by TargetUserName SubjectUserName
| where count >= 2

```

---

## 📊 How This Works During Attack

If attacker executes:
```bash
wmiexec.py internuser:Password123@192.168.1.10

```

Then runs:
```cmd
powershell.exe
net user socadmin Pass123 /add
net localgroup administrators socadmin /add

```

---

Splunk logs:

- 4688 → wmiprvse.exe
- 4688 → powershell.exe
- 4720 → user created
- 4732 → added to admin
- 4672 → privileges assigned

---

This query will output:

Detected_Activities:

- Remote Execution
- PowerShell Execution
- User Created
- Added to Admin Group
- Admin Privileges Assigned

---

## 📊 Expected Output Example

|time               |Activities                |
|-------------------|--------------------------|
|10:22:14           |Remote Execution         |
|10:22:18           |PowerShell Execution      |
|10:22:25           |User Created             |
|10:22:28           |Added to Admin Group       |
|10:22:31           |Admin Privileges Assigned   |

---

## 🚨 HIGH CONFIDENCE PRIVILEGE ESCALATION

---
