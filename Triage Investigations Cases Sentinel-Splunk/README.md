# SOC Analyst — Triage Case Repository

**Analyst:** Daniel Thibodeaux
**Platform:** MyDFIR SOC Simulator (mahcyberdefense.com)
**Environment:** Microsoft XDR / Sentinel / Splunk
**Period:** May 2026 – Present

---

## Overview

This repository documents real triage cases worked through the MyDFIR SOC Simulator. Each case includes the original alert, key raw alert fields, the investigation queries used, findings and IOCs, and a structured report following the 5W1H format. New cases are added as they are worked.

---

## Case Index

| # | Case | Severity | Verdict | Platform |
|---|---|---|---|---|
| 01 | [Credential Stuffing — MTS-ContractorPC1 (Incident 2130)](https://github.com/danielthibodeaux27/SOC-Portfolio/blob/main/Triage%20Investigations%20Cases%20Sentinel-Splunk/Case%2001%20credential%20stuffing%20mts%202130.md) | Low | True Positive — Unsuccessful | Sentinel |
| 02 | [Windows Run/RunOnce Registry Modification — mts-pc-1 (Incident 2139)](https://github.com/danielthibodeaux27/SOC-Portfolio/blob/main/Triage%20Investigations%20Cases%20Sentinel-Splunk/Case%2002%20run%20registry%20modified%20mts%202139.md) | Low | Benign — False Positive | Microsoft XDR |

---

## Skills Demonstrated

- Alert triage across Microsoft XDR, Sentinel, and Splunk
- KQL (Kusto Query Language) for Defender Advanced Hunting and Sentinel
- Identity-based detection investigation (credential stuffing vs. brute force)
- Process-lineage reconstruction and code-signing / PE metadata validation
- Distinguishing benign automated activity from adversary persistence
- OSINT enrichment — AbuseIPDB, threat-intel IP profiling
- IOC defanging, MITRE ATT&CK technique mapping, and 5W1H report writing
