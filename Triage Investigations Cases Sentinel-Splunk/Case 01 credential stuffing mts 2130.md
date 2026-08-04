# Case 01 — Credential Stuffing (MTS-ContractorPC1)

**Incident:** 2130 | **Severity:** Low | **Verdict:** True Positive — Attack Unsuccessful
**Date:** 2026-05-23 | **Platform:** Microsoft XDR / Azure Sentinel (SecurityEvent → DeviceLogonEvents)

---

## Alert

**Title:** Identity - Potential Credential Stuffing
**Description:** A single source IP attempting logins against many different accounts within a short period. This pattern is typical of credential stuffing (using leaked username/password pairs), and differs from brute force, which targets one account repeatedly.
**MITRE Tactic:** CredentialAccess | **Technique:** T1110
**Detection Source:** Azure Sentinel | **Provider:** Microsoft XDR
**Activity Window:** 2026-05-23T08:20:00Z – 2026-05-23T08:40:00Z (alert); attempts continued through ~12:40 UTC

---

## Raw Alert (Key Fields)

```json
{
  "Alert Name": "Identity - Potential Credential Stuffing",
  "IncidentId": "2130",
  "Status": "New",
  "Provider": "Microsoft XDR",
  "DetectionSource": "Azure Sentinel",
  "CorrelatedAlerts": 1,
  "MitreTactics": "CredentialAccess",
  "MitreTechniques": "T1110",
  "FirstActivity": "2026-05-23T08:20:00Z",
  "LastActivity": "2026-05-23T08:40:00Z"
}
```

---

## Queries Used

**Reproduce the detection — one IP hitting many accounts in a 10-minute window:**
```kql
set query_now = datetime(2026-05-23T12:47:46.7415958Z);
SecurityEvent
| where EventID == "4625"
| summarize Accounts = make_set(TargetAccount) by Computer, IpAddress, bin(TimeGenerated, 10m)
| extend DistinctAccounts_Count = array_length(Accounts)
| where DistinctAccounts_Count >= 5
```

**Pivot to confirm whether any attempt succeeded (updated to DeviceLogonEvents):**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-05-23T08:00:00Z) .. datetime(2026-05-23T13:00:00Z))
| where DeviceName == "mts-contractorpc1"
| where ActionType == "LogonSuccess"
```

---

## Findings

**IOCs:**
- Host: `MTS-ContractorPC1`
- IP: `124[.]156[.]231[.]67` — APNIC / data-center hosting, Tokyo, Japan; AbuseIPDB confidence ~35%, with prior history of Brute-Force, Hacking, and Port Scanning
- Accounts targeted: 30 distinct accounts across three consecutive 10-minute intervals — a mix of external consumer email domains, generic administrative roles, database identifiers, and office/server aliases (consistent with a pre-compiled credential dump list)
- EventID 4625 (Logon Failure): numerous
- EventID 4624 / `LogonSuccess`: **0**

---

## Investigation Summary

On 2026-05-23 between 08:20:00 UTC and 12:40:00 UTC, a Microsoft XDR alert fired for potential credential stuffing against `MTS-ContractorPC1`, originating from external IP `124[.]156[.]231[.]67`. KQL analysis confirmed the source IP cycled rapid authentication attempts against 30 distinct accounts across three consecutive 10-minute intervals, generating a large volume of Event ID 4625 (Logon Failure) entries. The targeted account list — external consumer email addresses alongside generic administrative and infrastructure labels — is characteristic of an automated spray using a third-party credential dump rather than a targeted attack on known users.

A follow-up pivot on `DeviceLogonEvents` for `LogonSuccess` on the same host and window returned **zero results**, confirming no attempt succeeded. Threat-intel profiling ties the IP to hosting infrastructure in Tokyo with prior abuse reports. The activity was a classic automated spray, successfully mitigated by existing authentication controls, with no unauthorized access and no ongoing activity.

**WHO:** External, unauthenticated attacker using APNIC/data-center infrastructure in Japan (`124[.]156[.]231[.]67`); target host `MTS-ContractorPC1`
**WHAT:** Credential stuffing (horizontal brute force) across dozens of distinct generic/external usernames — all attempts failed
**WHEN:** 2026-05-23 08:20 – 12:40 UTC — no longer ongoing
**WHERE:** `MTS-ContractorPC1`
**WHY:** To discover weak or reused credentials for initial unauthorized access via an exposed endpoint authentication interface
**HOW:** An automated script routed through a Japanese hosting-provider cloud instance sprayed a pre-compiled credential dump list against the host's authentication interface

---

## Recommendations

1. Add `124[.]156[.]231[.]67` to the corporate firewall blocklist, particularly if no business is expected with Japanese hosting-provider cloud instances.
2. Implement MFA on `MTS-ContractorPC1`, and restrict exposed network authentication interfaces (RDP/SMB) behind a corporate VPN gateway rather than exposing them directly.
3. Verify no generic default identifiers or credentials (e.g., `admin`/`admin`) are in use on the host.
