# Case 02 — Windows Run/RunOnce Registry Modification (mts-pc-1)

**Incident:** 2139 | **Severity:** Low | **Verdict:** Benign — False Positive (Legitimate Edge WebView2 Update)
**Date:** 2026-05-24 | **Platform:** Microsoft Defender XDR (Advanced Hunting)

---

## Alert

**Title:** Endpoint - Windows RUN Registry Modified
**Description:** Identifies changes made to the Windows `Run` / `RunOnce` registry keys, which control programs executed automatically at logon. Modifying these keys is a common persistence technique used by both legitimate software and threat actors (malware, RATs, living-off-the-land).
**MITRE Tactics:** Persistence, PrivilegeEscalation | **Technique:** T1547
**Detection Source:** Microsoft Defender Advanced Threat Protection | **Provider:** Microsoft XDR
**First/Last Activity:** 2026-05-24T16:56:18Z

---

## Raw Alert (Key Fields)

```json
{
  "Alert Name": "Endpoint - Windows RUN Registry Modified",
  "IncidentId": "2139",
  "Status": "New",
  "Provider": "Microsoft XDR",
  "DetectionSource": "Microsoft Defender ATP",
  "CorrelatedAlerts": 1,
  "MitreTactics": "Persistence, PrivilegeEscalation",
  "MitreTechniques": "T1547",
  "FirstActivity": "2026-05-24T16:56:18Z",
  "LastActivity": "2026-05-24T16:56:18Z"
}
```

---

## Queries Used

**Identify the triggering RunOnce write:**
```kql
DeviceRegistryEvents
| where DeviceName == "mts-pc-1"
| where Timestamp between (datetime(2026-05-24T16:50:00Z) .. datetime(2026-05-24T17:00:00Z))
| where RegistryKey has @"CurrentVersion\RunOnce"
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
```

**Reconstruct the full process lineage behind the write:**
```kql
DeviceProcessEvents
| where DeviceName == "mts-pc-1"
| where Timestamp between (datetime(2026-05-24T16:25:00Z) .. datetime(2026-05-24T17:00:00Z))
| where InitiatingProcessFileName in~ ("services.exe", "MicrosoftEdgeUpdate.exe", "setup.exe")
      or FileName in~ ("setup.exe", "MicrosoftEdgeUpdate.exe")
| project Timestamp, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

---

## Findings

- Host: `mts-pc-1`
- Process `setup.exe` wrote value `msedge_cleanup_{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}` to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- The value pointed back at `setup.exe` with arguments `--msedgewebview --delete-old-versions --system-level --verbose-logging` (a one-time cleanup task scheduled for next logon)
- Process lineage: `smss.exe → wininit.exe → services.exe → MicrosoftEdgeUpdate.exe /svc` (16:29:28 UTC) → Edge WebView2 update binary → two generations of `setup.exe`
- `setup.exe` is digitally signed by **Microsoft Corporation** (Microsoft Code Signing PCA 2024), valid and current; PE metadata consistent with "Microsoft Edge Installer"
- Executed under `NT AUTHORITY\SYSTEM` at System integrity; no associated user account
- No anomalous child processes, network connections, or follow-on activity
- Path: `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\148.0.3967.83\Installer`

**Verdict: Benign — False Positive.** The alert accurately fired on a real RunOnce modification, but the activity is a legitimate, Microsoft-signed component of the Edge WebView2 Runtime update process.

---

## Investigation Summary

On 2026-05-24 at 16:56:18 UTC, an alert fired on `mts-pc-1` after `setup.exe` wrote a `msedge_cleanup_{GUID}` value to the `RunOnce` key, scheduling a one-time cleanup at next logon. Tracing the process lineage showed the activity originated from the standard Windows service chain, with `MicrosoftEdgeUpdate.exe /svc` launching the WebView2 updater, which spawned two `setup.exe` generations — the first installing the new WebView2 archive, the second performing post-install cleanup of old version directories (the write that generated the alert).

File analysis confirmed `setup.exe` is validly signed by Microsoft, with internally consistent PE metadata for the Edge Installer, executing as SYSTEM with no user involvement and no follow-on activity. The behavior is routine, automated Edge WebView2 maintenance — not adversary persistence.

**WHO:** Host `mts-pc-1`; process ran as `NT AUTHORITY\SYSTEM` with no end-user account involved
**WHAT:** The Edge WebView2 updater (`setup.exe`) wrote a one-time RunOnce cleanup entry, which the Run/RunOnce monitoring rule flagged
**WHEN:** 2026-05-24 16:56:18 UTC, part of an update cycle beginning ~16:25 UTC — single, completed event
**WHERE:** `mts-pc-1`, under `...\EdgeWebView\Application\148.0.3967.83\Installer`
**WHY:** Routine, automated Edge WebView2 Runtime update maintenance that schedules removal of superseded version directories at next logon
**HOW:** `MicrosoftEdgeUpdate.exe` initiated a WebView2 update, spawning a chain of Microsoft-signed `setup.exe` processes; the final stage wrote a self-deleting RunOnce entry for post-update cleanup

---

## Recommendations

- No remediation action is required on this host. The activity was generated by a legitimate, Microsoft-signed component of the Edge WebView2 Runtime update process and does not indicate compromise, unauthorized access, or attacker persistence.
