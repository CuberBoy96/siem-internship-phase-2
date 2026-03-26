# Use Case 1 — Privilege Escalation via Remote Process Execution

## Attacker Machine
Kali Linux

## Victim Machine
Windows with Sysmon + Splunk

## Attack Flow

1. Discover Windows IP using Nmap
2. Connect using SMB
3. Execute remote command using wmiexec.py
4. Launch cmd.exe
5. Launch powershell.exe
6. Create new admin user

## Expected Logs

4624 — Network Logon  
4688 — Process Creation  
4672 — Privileged Access  
4720 — User Creation  
4732 — Admin Group Assignment
