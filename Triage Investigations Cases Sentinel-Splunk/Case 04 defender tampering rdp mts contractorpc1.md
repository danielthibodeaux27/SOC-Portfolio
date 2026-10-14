# Case 04 — Compromised Account and Defender Tampering (mts-contractorpc1)

**Alert ID:** da5582a1-6269-4ef9-aaff-8eb1bd48ed98_1 | **Severity:** High | **Verdict:** True Positive — Malicious (attack succeeded) | **Date:** 2026-10-10 (activity 2026-10-08 to 2026-10-11 UTC) | **Platform:** Microsoft Defender XDR (Advanced Hunting / KQL)

---

## Alert

- **Title:** Compromised account conducting hands-on-keyboard attack
- **Description:** The account shows behavior indicative of a hands-on-keyboard attack; an attacker may be using it to move laterally, and automated remediation may disable the account or device.
- **MITRE Tactic:** Defense Evasion | **Technique:** T1562.001 Disable or Modify Tools
- **Detection Source:** EDR | **Provider:** Microsoft Defender for Endpoint
- **Incident:** Compromised device (attack disruption), 17 alerts, 1 device, 1 user
- **Alert Window:** 2026-10-10T10:47:26Z – 2026-10-10T10:48:47Z (alert generated 10:50:23Z)

---

## Raw Alert (Key Fields)

```json
{
  "Alert Name": "Compromised account conducting hands-on-keyboard attack",
  "AlertId": "da5582a1-6269-4ef9-aaff-8eb1bd48ed98_1",
  "Status": "New",
  "Severity": "High",
  "Provider": "Microsoft Defender for Endpoint",
  "DetectionSource": "EDR",
  "DetectionTechnology": "Behavior,Network",
  "Device": "mts-contractorpc1",
  "User": "MTS-CONTRACTORP\\WDAGUtilityAccounts",
  "CorrelatedAlerts": 17,
  "MitreTactics": "DefenseEvasion",
  "MitreTechniques": "T1562.001",
  "FirstActivity": "2026-10-10T10:47:26Z",
  "LastActivity": "2026-10-10T10:48:47Z"
}
```

---

## Findings

True positive: a remote operator used valid administrator credentials over RDP, created a lookalike local account, disabled Microsoft Defender on mts-contractorpc1, and staged tooling. All times are UTC.

- **Host:** mts-contractorpc1, private IP 192.168.10.11, RDP (TCP 3389) reachable from the internet
- **Activity window:** 2026-10-08 06:00:11 (first administrator logon) to 2026-10-11 10:28:29 (last logon observed)
- **Accounts:** administrator which created WDAGUtilityAccounts on 2026-10-08 06:00:36. SID ending -1005, lookalike of the built-in WDAGUtilityAccount
- **Source IP:** 116[.]98[.]254[.]228 (Vietnam), all logons and RDP connections
- **Remote client:** DESKTOP-DV6MK6R, client-reported address 192.168.2.7
- **Defender tampering tool:** dControl.exe (Sordum Defender Control), HackTool:Win32/DefenderControl!MSR, SHA1 `cb704d2e8df80fd3500a5b817966dc262d80ddb8`, unsigned, run-time packed, VirusTotal 55/71
- **Staged tooling:** VNLIKE247.exe, 247file2012.ps1, rclone (downloads[.]rclone[.]org)
- **Defender impairment:** DisableRealtimeMonitoring, DisableAntiSpyware and DisableAntiVirus set to 1 at 10:48:52 to 10:48:58 on 2026-10-10
- **Other contact:** 103[.]9[.]204[.]151 connected to RDP at 2026-10-10 10:54:57; no logon recorded from it
- **MITRE ATT&CK:** T1078 Valid Accounts, T1021.001 RDP, T1136.001 Local Account, T1562.001 Disable or Modify Tools, T1059.001 PowerShell, T1105 Ingress Tool Transfer, T1070.004 File Deletion

---

## Investigation Summary

A remote operator logged in to mts-contractorpc1 over RDP as administrator from 116[.]98[.]254[.]228 on 2026-10-08 at 06:00 UTC, created a lookalike local account 25 seconds later, and returned on 2026-10-10 to disable Microsoft Defender and stage tooling. This is a true positive with high confidence. Logons from the same IP were still succeeding at the last observation, 2026-10-11 10:28 UTC.

On 2026-10-10 at 10:44 the operator connected as WDAGUtilityAccounts, a lookalike of the built-in WDAGUtilityAccount. Within five minutes they dropped dControl.exe, ran it as SYSTEM, and set the Defender disable values to 1. Defender flagged the tool as active malware but did not stop it, and the file was deleted by explorer.exe (the operator's own session) at 10:49:02, not by remediation. The operator then installed WinRAR, extracted vnlike.rar, ran a PowerShell script (247file2012.ps1) that set the system time zone to SE Asia Standard Time and downloaded rclone, pulled a second archive from a Google Drive with rclone, and launched VNLIKE247.exe, which made outbound connections at 10:56.

No lateral movement, shadow-copy commands, or credential-dumping commands were observed in the available telemetry, and none of the source IPs or the account appear on other devices. The purpose of the tooling, the contents of the script, and how the administrator credentials were obtained are not yet known.

---

## Who, What, When, Where, Why, How

The operator is unattributed; the evidence shows what they did and from where, not who they are. Where evidence is thin, the answer says so.

- **Who:** Unattributed operator connecting from 116[.]98[.]254[.]228 (Vietnam) with a client named DESKTOP-DV6MK6R that reported address 192.168.2.7. Accounts used: administrator, then WDAGUtilityAccounts. 103[.]9[.]204[.]151 also connected to RDP once; no logon from it was recorded.
- **What:** Logged in over RDP, created a lookalike account, ran dControl.exe as SYSTEM to disable Defender (registry values set to 1), deleted the tool, then staged and ran an unknown application (VNLIKE247.exe) with a PowerShell script and rclone.
- **When:** 2026-10-08 06:00:11 to at least 2026-10-11 10:28:29 UTC. Main activity 2026-10-10 10:44 to 10:56 UTC. Still active at last observation; current status is unconfirmed.
- **Where:** mts-contractorpc1 only (Azure VM, 192.168.10.11), reached directly on TCP 3389 from the internet. The IPs, account and file names do not appear on other devices in the available telemetry.
- **Why:** Not established. Defender was disabled to run unsigned tooling. VNLIKE247.exe looks like an automation application based on its Vietnamese filenames and proxy, cookie and Telegram settings files; this is inferred from names only.
- **How:** A valid administrator logon from 116[.]98[.]254[.]228 on 2026-10-08, with no failed logons from that IP beforehand, so the credentials were already known. The new account sat unused for about two days, then the operator used an RDP session to bring in tools and run them.

---

## Recommendations

Isolate the host and cut off the account first, then close the RDP exposure that let the operator in.

1. **Isolate mts-contractorpc1.** Logons from the operator's IP kept succeeding after the alert fired, so automated containment did not stop the account. Confirm isolation in the Action center.
2. **Disable WDAGUtilityAccounts and reset the administrator credentials.** End any active RDP sessions, and check where else the administrator password is used.
3. **Close public RDP.** Remove TCP 3389 exposure in the network security group and use Bastion, a VPN, or just-in-time access, with MFA and account lockout.
4. **Scope the IOCs across all hosts and all time:** SHA1 `cb704d2e8df80fd3500a5b817966dc262d80ddb8`, VNLIKE247.exe, vnlike.rar, 247file2012.ps1, rclone, WDAGUtilityAccounts, 116[.]98[.]254[.]228, 103[.]9[.]204[.]151, DESKTOP-DV6MK6R. None appear on other devices in the telemetry reviewed so far.
5. **Hunt for other lookalike or unexpected local accounts,** including the plural form WDAGUtilityAccounts.
6. **Rebuild the host from a known-good image.** The operator ran code as SYSTEM, so cleaning is not enough. Before the rebuild, collect the Desktop files and any rclone configuration for analysis.
7. **Restore Defender settings on any host touched.** Remove the DisableAntiSpyware and DisableAntiVirus values under the Windows Defender policy and product keys, and confirm Tamper Protection is on.
8. **Block 116[.]98[.]254[.]228 if you do not expect any traffic from Vietnam.** This is easy for an attacker to change, but blocking is low cost.

---

## Supporting Evidence

Times in Advanced Hunting are UTC.

### 1. Alert page

The alert story shows dControl.exe created by explorer.exe at 10:47:25, detected as HackTool:Win32/DefenderControl!MSR, with remote session initiator DESKTOP-DV6MK6R at 192.168.2.7.

### 2. Account creation

administrator created wdagutilityaccounts on 2026-10-08 at 06:00:36.

```kql
DeviceEvents
| where Timestamp between (datetime(2026-10-8 00:00) .. datetime(2026-10-11 11:00))
| where ActionType == "UserAccountCreated"
| project Timestamp, DeviceName, AccountName, InitiatingProcessAccountName, AccountSid, InitiatingProcessAccountSid
```

### 3. RDP logons

RemoteInteractive logons from 116.98.254.228 begin at 10:44:14 on 2026-10-10, preceded by network logons from the same IP and device name.

```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-10-10 00:00) .. datetime(2026-10-11 00:00))
| where AccountName =~ "wdagutilityaccounts"
| project TimeGenerated, ActionType, DeviceName, LogonType, AccountName, AccountSid, RemoteIP, RemoteDeviceName, RemoteIPType
```

### 4. Process execution

dControl.exe ran as SYSTEM and PowerShell executed Set-MpPreference. A SenseIR.exe row at 10:41:05 was reviewed and excluded as platform activity.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-10-10 10:42) .. datetime(2026-10-10 10:55))
| where DeviceName =~ "mts-contractorpc1"
| where FileName contains "dcontrol"
   or FileName =~ "powershell.exe"
   or ProcessCommandLine contains "Set-MpPreference"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessRemoteSessionIP
```

### 5. Defender registry changes

DisableRealtimeMonitoring, DisableAntiSpyware and DisableAntiVirus were set to 1 between 10:48:52 and 10:48:58, confirming the impairment succeeded.

```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2026-10-10 10:40) .. datetime(2026-10-10 11:00))
| where DeviceName =~ "mts-contractorpc1"
| where RegistryKey has "Windows Defender"
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryValueData, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by Timestamp asc
```

### 6. Script file events

247file2012.ps1 was created at 10:47:42 and edited in Notepad at 10:49:40. No origin URL was recorded.

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-10-10 10:40) .. datetime(2026-10-11 00:00))
| where DeviceName =~ "mts-contractorpc1"
| where FileName startswith "247file"
| project Timestamp, ActionType, FileName, FolderPath, SHA1, FileOriginUrl, FileOriginIP, InitiatingProcessFileName, InitiatingProcessAccountName
| sort by Timestamp asc
```

### 7. Post-exploitation activity chain

WinRAR, the script, rclone, the Google Drive download, and VNLIKE247.exe launch with outbound connections (shown in three frames).

```kql
union DeviceProcessEvents, DeviceNetworkEvents
| where DeviceName =~ "mts-contractorpc1"
| where Timestamp between (datetime(2026-10-10 10:49) .. datetime(2026-10-10 10:57))
| where InitiatingProcessFileName !in~ ("searchapp.exe","msedgewebview2.exe","smartscreen.exe")
| project Timestamp, Type, ActionType, FileName, ProcessCommandLine, RemoteIP, RemoteUrl, InitiatingProcessFileName
| sort by Timestamp asc
```

### 8. Inbound connections

Inbound RDP to 192.168.10.11:3389 from 116.98.254.228 at 10:44:06 and from 103.9.204.151 at 10:54:57, with no logon recorded from the second IP.

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-10-10 10:44) .. datetime(2026-10-10 11:10))
| where DeviceName =~ "mts-contractorpc1"
| where ActionType in ("InboundConnectionAccepted","IcmpConnectionInspected","ListeningConnectionCreated")
| project Timestamp, ActionType, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

### 9. Shadow-copy and credential-tool check

No shadow-copy or credential-dumping commands were observed (empty result).

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-10-10 10:44) .. datetime(2026-10-10 11:30))
| where DeviceName =~ "mts-contractorpc1"
| where FileName in~ ("vssadmin.exe","diskshadow.exe","wbadmin.exe","ntdsutil.exe","wmic.exe","reg.exe")
   or ProcessCommandLine has_any ("shadow","ntds","lsass","comsvcs","sam ")
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| sort by Timestamp asc
```

### 10. Logon scope

administrator logged on from 116.98.254.228 on 2026-10-08 at 06:00:11 and WDAGUtilityAccounts logons continue through 2026-10-11 10:28:29. Only mts-contractorpc1 appears, and there are no rows for 103.9.204.151.

```kql
DeviceLogonEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("116.98.254.228","103.9.204.151","51.224.252.206","45.150.242.95")
| summarize Events = count(), First = min(Timestamp), Last = max(Timestamp) by DeviceName, RemoteIP, ActionType, LogonType, AccountName
| sort by First asc
```

