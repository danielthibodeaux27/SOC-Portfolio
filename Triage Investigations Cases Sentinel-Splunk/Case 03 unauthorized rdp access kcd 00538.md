# Case 03 — Unauthorized RDP Access via Persistent Session (KCD-Web)

**Incident:** MYDFIR-2026-00538 | **Severity:** Medium (recommend escalation to High) | **Verdict:** True Positive — Malicious
**Date:** 2026-08-05 | **Platform:** Splunk (WinEventLog:Security)

---

## Alert

**Title:** KCD - Identity - Potential RDP Login Detected
**Description:** Identifies interactive logon activity on Windows hosts associated with Remote Desktop Protocol sessions, including new remote logons (Logon Type 10) and session unlock events (Logon Type 7). While RDP is routinely used for legitimate remote administration, adversaries abuse it for initial access, lateral movement, and hands-on-keyboard operations following credential compromise. Logon Type 7 events are of particular interest because an unlock implies a **pre-existing session** — requiring the analyst to identify the originating logon rather than treating the unlock as the start of the activity.
**MITRE Tactics:** Initial Access, Lateral Movement
**MITRE Techniques:** T1078.002 (Valid Accounts: Domain Accounts), T1021.001 (Remote Services: RDP)
**Detection Source:** Windows Security Event Log (WinEventLog:Security) | **Provider:** Splunk
**Activity Window:** First 2026-08-05T15:29:37Z → Last 2026-08-05T15:30:02Z | **Originating session established:** 2026-08-02T13:49:24Z

---

## Raw Alert (Key Fields)

```json
{
  "Alert Name": "KCD - Identity - Potential RDP Login Detected",
  "IncidentId": "MYDFIR-2026-00538",
  "Status": "Investigating",
  "Provider": "Splunk",
  "DetectionSource": "WinEventLog:Security",
  "Severity": "Medium",
  "CorrelatedAlerts": 1,
  "MitreTactics": "Initial Access, Lateral Movement",
  "MitreTechniques": "T1078.002, T1021.001",
  "FirstActivity": "2026-08-05T15:29:37Z",
  "LastActivity": "2026-08-05T15:30:02Z",
  "OriginatingSessionEstablished": "2026-08-02T13:49:24Z"
}
```

---

## Queries Used

**Surface the alerting Type 7 (unlock) event:**
```spl
index=endpoint sourcetype=WinEventLog host=KCD-Web EventCode=4624 Logon_Type=7
    earliest="08/05/2026:15:25:00" latest="08/05/2026:15:35:00"
| table _time host Account_Name Logon_Type Logon_Process Authentication_Package
        src_ip Logon_ID Linked_Logon_ID Security_ID
```

**Correlate session reconnect/disconnect events and client devices:**
```spl
index=endpoint sourcetype=WinEventLog host=KCD-Web (EventCode=4778 OR EventCode=4779)
| table _time EventCode Account_Name Client_Name Client_Address Session_Name Logon_ID
| sort _time
```

**Pivot on the session Logon ID to trace the originating Type 10 logon and any preceding failures:**
```spl
index=endpoint sourcetype=WinEventLog host=KCD-Web (EventCode=4624 OR EventCode=4625)
    (Logon_ID=0x62F95ECF OR src_ip=70.53.18.181)
| table _time EventCode Account_Name Logon_Type src_ip Logon_ID Status Sub_Status
| sort _time
```

---

## Findings

**Unauthorized external access to a privileged account confirmed — True Positive / Malicious.**

- Host: `KCD-Web.kerningcitydental.ca` — internet-reachable Windows server
- Compromised account: `kcd-administrator` (privileged domain account)
- Source IP: `70[.]53[.]18[.]181` — Bell Canada consumer broadband; no sanctioned association with this asset
- Alerting event: EventCode 4624, Logon Type 7 (unlock), Logon Process `User32`, session `RDP-Tcp#28`, Logon ID `0x7421E595`
- Originating session: EventCode 4624 Logon Type 10 (RemoteInteractive) on 2026-08-02 13:49:24 UTC, Logon ID `0x62F95ECF`, same source IP — **disconnected (4779), not logged off**, leaving a live session resident for ~3 days
- Preceding failure: EventCode 4625 for `kcd-contractor` at 2026-08-02 13:48:52 UTC, Sub_Status `0xC0000064` (**user does not exist** — naming-convention enumeration, not password guessing)
- Two distinct client devices behind the single IP: `Phone` (2026-08-02) and `Mahs-MacBook-Pr` (2026-08-05)
- All auth in the chain used **NTLM/Negotiate** (not Kerberos), null SID `S-1-0-0`, blank Workstation_Name on the Type 3 legs

**Indicators of Compromise**

| Type | Value | Context |
|---|---|---|
| IP | `70[.]53[.]18[.]181` | Source of RDP reconnect and originating Type 10 logon (Bell Canada broadband) |
| Hostname | `Mahs-MacBook-Pr` | RDP Client_Name on the 4778 reconnect, 2026-08-05 |
| Hostname | `Phone` | RDP Client_Name during the originating session, 2026-08-02 |
| Account | `kcd-administrator` | Compromised privileged domain account |
| Account | `kcd-contractor` | Targeted in failed enumeration (account does not exist) |
| Host | `KCD-Web.kerningcitydental.ca` | Affected asset |
| Session | `0x62F95ECF` | Logon ID of the persistent disconnected session |

---

## Investigation Summary

On 2026-08-05 at 15:29:38 UTC, an alert fired on `KCD-Web.kerningcitydental.ca` following a successful EventCode 4624 logon for `kcd-administrator` with **Logon Type 7 (unlock)** from external IP `70[.]53[.]18[.]181`. Because Type 7 denotes an unlock of a pre-existing interactive session rather than a new logon, the investigation focused on identifying the origin of that session rather than treating the unlock as the initial access point.

Correlating session identifiers showed that one second earlier, at 15:29:37 UTC, an EventCode 4778 ("session reconnected") was recorded for Logon ID `0x62F95ECF` from the same IP, with RDP client `Mahs-MacBook-Pr` on session `RDP-Tcp#28`. Pivoting on that Logon ID traced the session back to an EventCode 4624 **Logon Type 10 (RemoteInteractive)** on 2026-08-02 13:49:24 UTC from the identical source IP. Critically, the session was **disconnected (EventCode 4779) rather than logged off** at 2026-08-02 13:50:21 UTC, leaving it live for roughly three days and allowing the actor to resume on 2026-08-05 without re-authentication.

Reviewing authentication immediately before the originating Type 10 logon revealed an EventCode 4625 failure for `kcd-contractor` at 2026-08-02 13:48:52 UTC, Sub_Status `0xC0000064` (username does not exist). A single failed username followed 29 seconds later by a successful logon to a valid privileged account is consistent with an actor **already holding valid credentials** probing the org's naming convention — not brute force or spraying. RDP client metadata differed across the two access events from the same IP (`Phone` on 2026-08-02, `Mahs-MacBook-Pr` on 2026-08-05), indicating at least two client endpoints behind one external address. The session was disconnected again at 15:30:02 UTC. No evidence indicates the activity was authorized.

**WHO:** Unauthorized external actor operating from `70[.]53[.]18[.]181` using the privileged account `kcd-administrator`, via RDP client `Mahs-MacBook-Pr` (and `Phone` during the originating session); target host `KCD-Web.kerningcitydental.ca`
**WHAT:** A pre-existing RDP session for `kcd-administrator` — originally established 2026-08-02 and left disconnected-but-live — was reconnected and unlocked from an external IP, resuming access without re-authentication
**WHEN:** Alerting unlock 2026-08-05 15:29:38 UTC (reconnect 15:29:37 → disconnect 15:30:02); originating RemoteInteractive logon 2026-08-02 13:49:24 UTC. Activity is intermittent; the actor has demonstrated the ability to return
**WHERE:** `KCD-Web.kerningcitydental.ca`, an internet-reachable Windows server, over RDP session `RDP-Tcp#28`
**WHY:** Unauthorized remote access to a compromised privileged account; the retained disconnected session provided persistent access requiring no re-authentication and generating no new logon on return
**HOW:** Authenticated over RDP with valid `kcd-administrator` credentials on 2026-08-02 after a single failed username enumeration of `kcd-contractor`; disconnected rather than logged off, leaving the session resident; reconnected 2026-08-05 from a different client device behind the same IP, producing the 4778 reconnect and the Type 7 unlock that triggered this alert

---

## Recommendations

1. **Terminate** session Logon ID `0x62F95ECF` on KCD-Web with an explicit logoff (`logoff <sessionid> /server:KCD-WEB`). Disconnecting is insufficient — the disconnected state is the mechanism that enabled this access.
2. Reset credentials for `kcd-administrator` and force invalidation of existing sessions; review the account for unauthorized privilege or group-membership changes.
3. Block `70[.]53[.]18[.]181` at the perimeter firewall and add it to threat-intel blocklists.
4. Remove direct internet exposure of RDP (TCP/3389) on KCD-Web; require access via VPN or a managed jump host with MFA enforced.
5. Configure an RDP session-timeout policy to force logoff of disconnected sessions after a defined idle period rather than retaining them indefinitely — this closes the persistence mechanism used here.
6. Audit all other accounts with active or disconnected sessions on KCD-Web, and review authentication history for `70[.]53[.]18[.]181` across the estate.
7. **Escalate severity from Medium to High.** The alert describes a login event; the confirmed finding is unauthorized external access to a privileged account on an internet-facing server with a three-day dwell time.
8. **Detection tuning:** the current rule surfaces Logon Type 7 without correlating to the originating session. Enrich the detection to join EventCode 4778/4779 and the parent Logon ID so the analyst is presented with the true session origin at triage time.
