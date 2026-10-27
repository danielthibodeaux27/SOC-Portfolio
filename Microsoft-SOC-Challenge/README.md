# Microsoft SOC Challenge

A 30-day project building a Microsoft-native SOC lab from scratch and working it like an analyst — Microsoft Sentinel, Defender XDR, Defender for Office 365, and Entra ID.

Part of the [MyDFIR](https://www.mydfir.com/) 30-Day Microsoft SOC Analyst Challenge.

**Timeline:** September 14 – October 13, 2026 · **Status:** Complete (30 of 30 days). The lab was torn down on October 13, 2026.

---

## Contents

- [Overview](#overview)
- [Lab setup](#lab-setup)
- [What was built](#what-was-built)
- [Data sources](#data-sources)
- [KQL](#kql)
- [Detection built](#detection-built)
- [Investigation reports](#investigation-reports)
- [Email security configuration and validation](#email-security-configuration-and-validation)
- [Endpoint hardening and validation](#endpoint-hardening-and-validation)
- [Threat hunting](#threat-hunting)
- [Identity and access](#identity-and-access)
- [Final mini project: Incident 810](#final-mini-project-incident-810)
- [Dashboard](#dashboard)
- [Day-by-day log](#day-by-day-log)
- [Reflection](#reflection)
- [Skills demonstrated](#skills-demonstrated)

---

## Overview

**What this is.** A full cloud SOC lab built end to end: identity, email, endpoint, and SIEM, with detections written and investigations reported against the telemetry it produces.

**Why I built it.** My portfolio was already strong on Elastic, Splunk, and on-prem Active Directory. This closes the Microsoft/Azure gap that most SOC job descriptions ask for by name.

**Tools used**

- Microsoft Sentinel — analytics rules, workbooks, incidents, KQL hunting, Content hub, data connectors (Defender XDR, Entra ID)
- Microsoft Defender XDR — unified incident queue, automatic attack disruption, Action Center, data connector into Sentinel
- Defender for Endpoint — endpoint telemetry and advanced hunting
- Defender for Office 365 — phishing investigation, Threat Explorer, Safe Links, anti-phishing policy, quarantine, attack simulation training
- Microsoft Entra ID — identity, sign-in and audit logs, Conditional Access, named locations
- Microsoft Intune — endpoint security policy (attack surface reduction)
- Atomic Red Team — adversary simulation for detection validation
- Azure Log Analytics, Azure Cost Management
- KQL, MITRE ATT&CK

**Skills practiced**

- Writing and explaining KQL against Microsoft security tables
- Building scheduled analytics rules with entity mapping and ATT&CK alignment
- Triaging alerts to a verdict and writing the investigation up
- Building dashboards that match what the data can actually support
- Standing up and troubleshooting cloud infrastructure
- Configuring email threat policies and proving them with test messages and hunting queries
- Working a user-reported phish from report to verdict, and reading a credential-harvest simulation
- Enforcing an endpoint control and verifying it on the endpoint, not only in the portal
- Validating detections with adversary simulation and tracing alerts back to raw telemetry
- Hunting from a written hypothesis with no alert to follow, and reporting when the data can't answer it
- Building a Conditional Access policy and proving it in the sign-in logs
- Onboarding Entra ID logs into Sentinel and confirming them with KQL
- Investigating an incident where automated response acted before the analyst did

---

## Lab setup

Hybrid — Azure for the SIEM, local hardware for the endpoint.

| Layer | Where it runs |
|---|---|
| SIEM / analytics | Azure — Microsoft Sentinel on Log Analytics |
| Identity | Microsoft 365 E5 trial tenant (Entra ID) |
| Email security | Defender for Office 365 |
| Endpoint | Windows 11 VM in VMware Workstation, local hardware |
| Endpoint management | Microsoft Intune (Microsoft 365 E5 trial tenant) |

The endpoint runs locally because free Azure credits won't provision a VM without converting the subscription to pay-as-you-go.

**Naming convention:** `mdf-dt-<type>-<purpose>-<##>` — `mdf` groups all challenge resources for easy filtering and cleanup, `dt` is my initials.

VM names stay at 15 characters or fewer. Windows still enforces the NetBIOS computer-name limit, and a longer Azure resource name silently desyncs from the OS hostname — which breaks host correlation between Defender for Endpoint and Sentinel.

**Cost controls**

- Azure Cost Management budget `MyDFIR-Challenge` at $10/month with alerting
- Every resource tagged `Project=MyDFIR-M365` · `Owner=Daniel` · `Environment=Lab` · `DeleteAfter=2026-10-13`
- Both E5 trials set to cancel on expiration rather than convert to paid

**Result:** Azure Cost Management showed $0.00 for both September and October 2026, so the whole lab ran at no cost.

---

## What was built

Everything in this table was torn down on October 13, 2026, when the E5 trial ended.

| Resource | Name | Region |
|---|---|---|
| Resource group | `mdf-dt-rg-lab-02` | West US |
| Log Analytics workspace | `mdf-dt-law-sentinel-02` | West US |
| Microsoft Sentinel | on `mdf-dt-law-sentinel-02` | West US |
| Sentinel Training Lab | 11+ tables, 18/22 detection rules live | West US |
| Sentinel workbook | `mdf-dt-wb-soc-overview-01` | West US |
| Custom analytics rule | `mdf-dt-rule-failed-logon-bruteforce-01` | West US |
| Windows 11 endpoint | `MDF-DT-W11` | On-prem (VMware) |
| Lab users | `richard.hale` (CFO, Finance) and `robert.smith` | Tenant |
| Safe Links policy | `mdf-dt-safelinks-allusers-01` | Tenant |
| Anti-phishing policy | `mdf-dt-antiphish-allusers-01` | Tenant |
| Attack simulation | `mdf-dt-sim-credential-harvest-01` | Tenant |
| Defender for Endpoint onboarding | `MDF-DT-W11` | Tenant |
| Intune ASR policy | `mdf-dt-asr-policy-01` | Tenant |
| Entra device group | `mdf-dt-grp-asr-test-01` | Tenant |
| Conditional Access named location | `mdf-dt-nl-blocked-countries-01` (Japan) | Tenant |
| Conditional Access policy | `mdf-dt-ca-block-country-01` (Block, On) | Tenant |
| Entra ID data connector | on `mdf-dt-law-sentinel-02` (Sign-in Logs, Audit Logs) | West US |

An earlier resource group and workspace (`mdf-dt-rg-lab-01` / `mdf-dt-law-sentinel-01`, West US 2) were superseded during the Training Lab deployment — see Day 4 below.

The endpoint is Entra-joined as a dedicated **non-admin** user licensed with E5, not as my admin account. Identity and privilege-escalation scenarios later in the challenge only produce realistic telemetry if they start from an ordinary user's endpoint.

---

## Data sources

**Connectors.** On Day 6, 8 data connectors were available and 7 connected. The Microsoft Defender XDR connector is wired into `mdf-dt-law-sentinel-02`, with Defender Alerts fully connected (`AlertInfo`, `AlertEvidence`) so Defender detections land in the Sentinel incident queue alongside Sentinel's own. Day 27 added the Microsoft Entra ID connector (`SigninLogs`, `AuditLogs`), for 9 available and 8 connected. See [Identity and access](#identity-and-access).

![Sentinel data connectors](screenshots/day06-01-data-connectors-overview.png)

**Tables confirmed populated (Day 5 inventory):**

```kql
union withsource=TableName *
| summarize Events = count() by TableName
| sort by Events desc
```

| Table | Events | What it gives me |
|---|---|---|
| `ExposureGraphNodes` | 1,103,105 | Attack surface and asset relationships |
| `GraphAPIAuditEvents` | 2,280 | Graph API activity |
| `EntraIdSignInEvents` | 112 | Identity sign-in telemetry |
| `SecurityEvent` | 18,163 failed logons | Windows security event log |
| `Watchlist` | 16 | Training Lab watchlists |
| `SecurityIncident` / `SecurityAlert` | 2 / 2 | Sentinel incidents and alerts |
| `AlertEvidence` / `AlertInfo` / `IdentityInfo` | 2 / 1 / 1 | Defender XDR enrichment |

---

## KQL

All queries are in [`kql/`](kql/), each with a header comment explaining what it looks for and why.

**Failed logon summary**

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, Computer
| sort by FailedAttempts desc
```

Event ID 4625 is Windows logging *an account failed to log on*. This filters to those events, counts them per account-and-host pair, and sorts the highest to the top.

**Why it matters:** a burst of failed logons is the classic signature of brute force or password spraying. Summarizing by account *and* host is what lets you tell them apart — many failures against one account is brute force, few failures across many accounts is spraying, and spraying is the one that slips past lockout policy.

**Result:** `\ADMINISTRATOR` on host `SOC-FW-RDP` with nearly 10,000 failed attempts — an admin account being hammered on an RDP-exposed host.

**Safe Links click tracing**

```kql
EmailEvents
| where RecipientEmailAddress contains "richard"
| where SenderFromAddress =~ "phishingmydfir@gmail.com"
| project Timestamp, UrlCount, Subject, SenderFromAddress, RecipientEmailAddress, DeliveryAction, DeliveryLocation, NetworkMessageId
| sort by Timestamp asc

UrlClickEvents
| where AccountUpn startswith "richard.hale@"
| project Timestamp, AccountUpn, Url, ActionType, Workload, IsClickedThrough
```

Safe Links rewrites a link at delivery and logs the click in `UrlClickEvents`. The first query lists the messages from one sender to one recipient; the second lists that recipient's clicks. Matching `NetworkMessageId` across the two ties a click to the exact email that carried the link. Full version with notes: [`safelinks-click-tracing.kql`](kql/safelinks-click-tracing.kql).

**Why it matters:** the same ID is how a click, an Explorer entry, and a user report all point at one message. `IsClickedThrough` means the user clicked past a warning page, not that they clicked the link.

**Result:** the 11:50 AM message had `UrlCount` 1, and `UrlClickEvents` showed one `ClickAllowed` row for `https://google.com/` with `IsClickedThrough` 0. `UrlClickEvents` was empty right after the click and filled in later because of ingestion delay.

**Run key persistence (Atomic Red Team)**

```kql
DeviceRegistryEvents
| where DeviceName =~ "mdf-dt-w11"
| where RegistryKey contains "CurrentVersion\\Run"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```

Run and RunOnce keys are where Windows looks for programs to start at logon, so a write to them is a classic persistence signal. This returns every write with the command that made it.

**Why it matters:** the value data shows what will run and the command line shows who wrote it, which is enough to separate a software installer from a script planting a payload.

**Result:** two rows from the Atomic Red Team tests: a HKCU `Run` value pointing at `C:\Path\AtomicRedTeam.exe`, and a HKLM `RunOnce` value holding a PowerShell command that downloads and runs a script. The RunOnceEx write (most likely test 2) left no row here. Its `reg.exe` command line was only visible in `DeviceProcessEvents` ([`reg-exe-runonce-process.kql`](kql/reg-exe-runonce-process.kql)), and the scheduled task test was only in `DeviceEvents` ([`scheduled-task-created.kql`](kql/scheduled-task-created.kql)). Telemetry coverage differs by table, so one query is not enough.

**Added in Days 22–27**

| File | Day | What it does |
|---|---|---|
| [`scheduled-task-hunt.kql`](kql/scheduled-task-hunt.kql) | 22 | Four-step hunt for scheduled task persistence, from all task creations down to the creating command line |
| [`cloudappevents-coverage.kql`](kql/cloudappevents-coverage.kql) | 22 | Coverage check before an inbox rule hunt. The table was empty, which made the hypothesis untestable. |
| [`entra-signin-logs.kql`](kql/entra-signin-logs.kql) | 27 | Confirms `SigninLogs` is flowing, with result codes and Conditional Access status |
| [`entra-audit-policy-changes.kql`](kql/entra-audit-policy-changes.kql) | 27 | Confirms `AuditLogs` is flowing, filtered to policy changes |

---

## Detection built

**`mdf-dt-rule-failed-logon-bruteforce-01`** — a scheduled analytics rule written from scratch, not imported from a template.

| Setting | Value |
|---|---|
| Severity | Medium |
| MITRE ATT&CK | Credential Access — T1110 (Brute Force) |
| Frequency | Every 1 hour |
| Lookback | Last 14 days |
| Threshold | Alert if query returns more than 0 results |
| Event grouping | Trigger an alert for each event |
| Entity mapping | Account → `FullName` = `Account` · Host → `HostName` = `Computer` |

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by Account, Computer
| where FailedLogons >= 1000
| sort by FailedLogons desc
```

![Rule logic and query results](screenshots/day06-05-rule-logic-query.png)

**Why the threshold is 1,000.** A handful of failed logons is a user mistyping a password. The interesting signal here is volume, so the rule only fires on accounts crossing four figures within the lookback window. That's deliberately tuned to this dataset — in production the number would come from baselining normal failure rates per host, not from picking a round number.

**Why entity mapping matters.** Without it, Sentinel treats an alert as a row of text. Mapping `Account` and `Computer` to the Account and Host entities lets the platform pivot — click the account and see everything else it touched, build an investigation graph, correlate across rules. An unmapped rule fires but can't be investigated from inside the product.

The rule went live and generated three incidents against the accounts crossing the threshold.

![Incidents generated by the rule](screenshots/day06-08-incidents-list.png)

---

## Investigation reports

| Day | Investigation | Verdict | Report |
|---|---|---|---|
| 7 | Multiple failed logons — 18,163 events across 3 hosts | True positive, unsuccessful | [`reports/day07-failed-logon-alert-report.md`](reports/day07-failed-logon-alert-report.md) |
| 16 | Suspicious email — simulated "Microsoft Support Team" password-expiry phish to the CFO test user | Phish, quarantined by Exchange Online Protection (High Confidence), not in the mailbox | [`reports/day16-suspicious-email-report.md`](reports/day16-suspicious-email-report.md) |
| 23 | High severity alert — *Compromised account conducting hands-on-keyboard attack*, raised by the Day 20 scheduled task test | True positive for the behavior, benign in intent (authorized Atomic Red Team test) | [`reports/day23-high-severity-alert-report.pdf`](reports/day23-high-severity-alert-report.pdf) |
| 29 | Final mini project — Incident 810: Mimikatz and Atomic Red Team T1082 on the lab endpoint, plus a phishing lure and a risky sign-in | True positive, controlled lab exercise. Attack disruption contained the user and isolated the device. | [`reports/day29-incident-810-report.pdf`](reports/day29-incident-810-report.pdf) |

Reports follow the structure I use for casework: **Findings → Summary → 5W1H → Recommendations → Supporting evidence**, with estimative language (*likely / probable / almost certain*) wherever the evidence supports an assessment but not a conclusion. If it can't be backed with evidence, it doesn't go in the report.

---

## Email security configuration and validation

Day 10 sets up the two lab users, and Days 11-15 cover Defender for Office 365: reviewing the default policies, building two of my own, and testing them with messages from an external Gmail account to the CFO test user. Day 14 had no assignment, so I used it to explore the user-reported phish workflow. The Day 16 mini project is the suspicious email report in the table above.

| Day | Work | Result |
|---|---|---|
| 10 | Created the lab users: a CFO in Finance and a second user, each licensed Microsoft 365 E5 (no Teams) | Both users show as licensed in Active users, and the CFO user has the default role with no admin center access. A test email sent between the two users was delivered, which confirmed the mailboxes worked before any policies were built. |
| 11 | Reviewed the threat policies and recorded the tenant baseline | Only the default anti-phishing policy existed and Built-in protection was the only active preset. Configuration analyzer listed 18 findings, 12 of them anti-phishing. In the default anti-spam policy, the high-confidence spam and phishing email detection actions are Move to Junk Email folder, and the default anti-phishing impersonation action is "No action". |
| 12 | Built Safe Links policy `mdf-dt-safelinks-allusers-01` (URL rewriting, real-time scanning, click tracking on, click-through off) | A test link was rewritten to a safelinks URL, and `UrlClickEvents` logged a ClickAllowed row whose `NetworkMessageId` matched the email in `EmailEvents`. |
| 13 | Built anti-phishing policy `mdf-dt-antiphish-allusers-01` (threshold 3, CFO user protected, impersonation and spoof actions set to Quarantine) | Configuration analyzer moved from 12 to 14 anti-phishing findings. The 12 default-policy findings remain because the default policy sits unchanged underneath. |
| 14 | No assignment. Worked a user-reported phish through Submissions and Explorer | Marked it Phishing, and the reporter received the follow-up email. The report's subject carries the original `NetworkMessageId`, so it pivots straight into hunting. A report covers only the one message, so scoping needs a sender search. |
| 15 | Sent a BEC-style lure and ran credential-harvest simulation `mdf-dt-sim-credential-harvest-01` against both lab users | The BEC-style lure reached the Inbox with Threat type None. Safe Links rewrote its link and a first-contact tip appeared, but nothing blocked it. In the simulation, 1 of 2 users was compromised as of the report capture (the simulation was still in progress): the CFO test user clicked, supplied credentials, and was assigned two training courses. The simulation email itself never appeared in `EmailEvents` or Explorer, only the training notifications did. |

![Adding the CFO test user: license, default role, and profile](screenshots/day10-03-review-non-admin-role.png)

![Active users, all licensed Microsoft 365 E5 (no Teams)](screenshots/day10-06-active-users-licensed.png)

![Test email delivered between the two lab users](screenshots/day10-09-test-email-received.png)

![Configuration analyzer baseline](screenshots/day11-05-configuration-analyzer-standard.png)

![Safe Links rewrote the link](screenshots/day12-10-owa-richard-link-rewritten.png)

![Click logged in UrlClickEvents](screenshots/day12-12-urlclickevents-richard.png)

![Configuration analyzer after the anti-phishing policy](screenshots/day13-10-config-analyzer-antiphish.png)

![BEC-style lure with Safe Links rewrite and first-contact tip](screenshots/day15-03-outlook-safelinks-url-rewrite-hover-annotated.png)

![Credential-harvest simulation report](screenshots/day15-14-sim-report-overview.png)

---

## Endpoint hardening and validation

Beyond investigating alerts, the challenge also covers onboarding the endpoint, hardening it, and proving the detections work. Day 19 and Day 20 are hands-on exercises rather than investigations, so their writeups live in [`writeups/`](writeups/) instead of the reports folder.

| Day | Work | Result | Writeup |
|---|---|---|---|
| 17 | Onboarded the Windows 11 endpoint to Defender for Endpoint with the local script and ran the detection test | The device shows Onboarded and Active in Device Inventory. | None |
| 18 | Investigated two events on the device timeline: an EICAR test file and a PowerShell detection test | EICAR was prevented by antivirus before `explorer.exe` could open it. The PowerShell test was caught by EDR on a signed Microsoft binary, tagged T1059.001. Both were expected test activity, and the two alerts landed as separate incidents (808 and 809). | None |
| 19 | Intune attack surface reduction policy, four rules in Block, scoped to a one-device group | Intune reported Succeeded 1, and all four rules were enforcing on the endpoint | [`writeups/day19-asr-policy-writeup.md`](writeups/day19-asr-policy-writeup.md) |
| 20 | Atomic Red Team: registry run keys and a scheduled task | Defender XDR raised persistence alerts and a High alert, then contained the account through attack disruption | [`writeups/day20-atomic-red-team-writeup.md`](writeups/day20-atomic-red-team-writeup.md) |

Enforcement on Day 19 is verified by configuration on the endpoint, not by a live block.

**Found later: Day 20 also isolated the device.** The Day 20 writeup records only the Contain user action. On Day 28, Action Center history showed the full sequence for October 5 (UTC): Contain user at 23:09, my release of the user containment at 23:55, then attack disruption ran **Isolate device** on MDF-DT-W11 at 23:59, four minutes after the release. I didn't notice that isolation at the time, so the VM stayed isolated for nearly a week until I stopped it on October 12 at 18:03 UTC. Contain user and Isolate device are separate actions, and releasing one does not release the other.

![Device onboarded](screenshots/day17-06-device-inventory-onboarded.png)

![PowerShell test alert, process detail](screenshots/day18-04-powershell-event-details.png)

![Endpoint verification](screenshots/day19-18-get-mppreference-asr.png)

![Alerts after the Atomic Red Team tests](screenshots/day20-06-alerts-list-after-tests.png)

---

## Threat hunting

Days 21–22 were hunting with no alert to follow: write a hypothesis, decide what data would prove or disprove it, and report what the data actually supports. Full writeup: [`writeups/day22-threat-hunting-writeup.md`](writeups/day22-threat-hunting-writeup.md).

| Hypothesis | ATT&CK | Result |
|---|---|---|
| A new scheduled task runs a binary or script from a user-writable path | T1053.005 | **Partially supported.** 87 task creations in 30 days and 0 in user-writable paths. The one task that mattered, my Day 20 test task `spawn`, runs `cmd.exe` from System32, so the path filter would have missed it. |
| A phished account creates an inbox rule to hide security or reply emails | T1564.008 | **Could not be tested.** `CloudAppEvents` had zero rows in 30 days, so Exchange activity wasn't reaching Advanced Hunting. That is a logging coverage finding, not evidence about attacker behavior. |

Starting broad and narrowing (87 → 0) showed exactly where the hypothesis broke, which a query filtered to my known task never would have.

![schtasks.exe command line in DeviceProcessEvents](screenshots/day22-05-schtasks-process-events.png)

![CloudAppEvents empty over 30 days](screenshots/day22-06-cloudappevents-coverage.png)

---

## Identity and access

Days 24–27 moved to Microsoft Entra ID: a walkthrough of the Entra admin center (Days 24 and 26, no lab work), a Conditional Access policy, and Entra ID logs flowing into Sentinel.

| Day | Work | Result | Writeup |
|---|---|---|---|
| 25 | Disabled security defaults so Conditional Access could be enabled. Built named location `mdf-dt-nl-blocked-countries-01` (Japan) and policy `mdf-dt-ca-block-country-01` (Block access, all resources, On) | A sign-in as the CFO test user through a Tokyo VPN exit hit *You cannot access this right now*, and the sign-in log recorded **error 53003** with the policy named as Block, Failure | [`writeups/day25-conditional-access-writeup.md`](writeups/day25-conditional-access-writeup.md) |
| 27 | Installed the Entra ID solution from Content hub and connected the Entra ID data connector (Sign-in Logs, Audit Logs) | After fresh telemetry was generated, `SigninLogs` showed the 53003 block from Japan and `AuditLogs` showed a Conditional Access policy update | [`writeups/day27-entra-id-connector-writeup.md`](writeups/day27-entra-id-connector-writeup.md) |

The connector only forwards events from the moment it's enabled, so the first queries came back empty until I generated new sign-ins.

![Sign-in blocked by Conditional Access](screenshots/day25-07-signin-blocked-page.png)

![Sign-in details: error 53003](screenshots/day25-09-signin-error-53003.png)

![SigninLogs in Sentinel after connecting Entra ID](screenshots/day27-02-signinlogs-query.png)

---

## Final mini project: Incident 810

On Day 28 I generated activity across email, identity, and endpoint, and on Day 29 I wrote it up as a formal incident report: [`reports/day29-incident-810-report.pdf`](reports/day29-incident-810-report.pdf).

**What happened on October 12 (UTC)**

| Time | Activity |
|---|---|
| ~16:37 | First send of an "Invoice is ready for viewing" lure from a new external Outlook.com account to the CFO test user, blocked by Microsoft's sender-abuse detection on the new account |
| 17:08 | Second send succeeded and was quarantined by Exchange Online Protection as **High Confidence Phish**. The "View Invoice" link pointed to an unrelated domain. |
| 17:21 | The CFO test user signed in successfully from a VPN exit in Bucharest, Romania. Romania wasn't in the Conditional Access block list, no MFA challenge occurred, and Identity Protection raised no risk detection. |
| 17:40–17:55 | First Mimikatz alerts in Incident 810 (*Mimikatz credential theft tool*, *Potential human-operated malicious activity*, *Malicious credential theft tool execution detected*) |
| 18:03 | Stopped the device isolation left over from Day 20 |
| 18:06 | Downloaded Mimikatz. Defender Antivirus blocked the archive, so I added a temporary Temp-folder exclusion to continue the exercise. |
| 18:14 | `mimikatz.exe` executed and was caught by EDR behavioral detection, which the exclusion did not affect |
| 18:16 | Attack disruption: **Contain user** |
| 18:18 | Defender quarantined the T1059.001 test definition from an earlier attempt, so I switched to T1082 (System Information Discovery) |
| 18:20 | T1082 sub-tests ran |
| 18:22 | Attack disruption: **Isolate device** |

The report narrates the 18:06–18:35 sequence. The incident's alert list shows Mimikatz alerts from 17:40, so the Oct 12 activity window is 17:40–18:35 UTC.

**One incident across a week.** Incident 810's first activity is October 5 at 22:49:21 UTC, the Meterpreter and PowerSploit alerts from the Day 20 Atomic Red Team install. Defender grouped the Day 20 and Day 28 activity on the same device and user into one incident a week apart. The Day 23 High alert most likely belongs to the same incident.

**Takeaways from the report**

- Static antivirus caught the file and behavioral EDR caught the execution, so the exclusion didn't blind the endpoint.
- Contain user and Isolate device fire separately and have to be released separately. Check Action Center history so nothing gets left in place, as the Day 20 isolation was.
- Identity Protection's risk detections depend on sign-in history. A first-ever sign-in from Romania raised nothing, most likely because the test account had no baseline.

![Defender Antivirus blocking the Mimikatz archive](screenshots/day28-01-mimikatz-av-block.png)

![Action Center history: Day 20 and Day 28 actions](screenshots/day28-02-action-center-history.png)

![Incident 810 attack story](screenshots/day28-03-incident-810-attack-story.png)

![Invoice lure quarantined as High Confidence Phish](screenshots/day28-04-quarantine-invoice-phish.png)

![Sign-ins from Romania](screenshots/day28-05-romania-signins.png)

---

## Dashboard

**Workbook:** `mdf-dt-wb-soc-overview-01`

Baseline monitoring for the lab. Default time range 30 days.

| Panel | Query basis | Visualization |
|---|---|---|
| Top 5 Failed Logins | `SecurityEvent` · `EventID == 4625` · by `Account` | Donut |
| Failed Logons by Target Host | `SecurityEvent` · `EventID == 4625` · by `Computer` | Bar + tiles |
| Event Volume by Event ID | `SecurityEvent` · by `EventID` | Tiles |

![Top 5 failed logins](screenshots/day05-01-workbook-failed-logins.png)

![Failed logons by host and event volume](screenshots/day05-02-workbook-host-event-volume.png)

**One thing worth noting about the data.** The Training Lab telemetry is bulk-ingested, not streamed, so `TimeGenerated` and `TimeCollected` both reflect ingestion time. All 18,163 failed logons carry a single timestamp, which means a "failed logons over time" chart renders one giant spike and says nothing. I built categorical panels instead.

`LogonTypeName` is also unpopulated in this dataset, so the network / RDP / interactive breakdown isn't available here. Both would be standard panels in a production workspace.

---

## Day-by-day log

| Day | What I did |
|---|---|
| 1 | Azure account, $10 budget with alerting, naming convention, lab plan and schedule |
| 2 | Built the Windows 11 endpoint on-prem in VMware; created a non-admin Entra user licensed E5 and Entra-joined the VM as that user |
| 3 | Walked the Sentinel tabs; created the Log Analytics workspace |
| 4 | Deployed the Sentinel Training Lab; ran three KQL queries |
| 5 | Built the SOC Overview workbook; inventoried the available tables |
| 6 | Connected the Defender XDR data connector; built and enabled my first custom analytics rule, which fired and created three incidents |
| 7 | Investigated the failed-logon alert end to end and wrote the full report |
| 8 | Hunted `OfficeActivity_CL` with no alert to follow; found a file access from an off-baseline IP, bookmarked it and promoted it to an incident |
| 9 | Portfolio setup — this writeup |
| 10 | Created the lab users (a CFO in Finance and a second user) with E5 (no Teams) licenses and confirmed mail flow with a test email between them |
| 11 | Reviewed the Defender for Office 365 threat policies and recorded the tenant baseline (default anti-phishing policy only, 18 Configuration analyzer findings) |
| 12 | Built a Safe Links policy and confirmed a test link was rewritten and the click was logged in `UrlClickEvents` |
| 13 | Built an anti-phishing policy protecting the CFO test user, with impersonation and spoof actions set to Quarantine |
| 14 | No assignment. Worked a user-reported phish through Submissions and Explorer and marked it Phishing |
| 15 | Sent a BEC-style lure that reached the Inbox, and ran a credential-harvest simulation (1 of 2 users compromised) |
| 16 | Mini project: investigated a simulated password-expiry phish, quarantined as High Confidence Phish, and wrote the report |
| 17 | Onboarded the Windows 11 endpoint to Defender for Endpoint |
| 18 | Investigated two events on the device timeline: an EICAR test file prevented by antivirus and a PowerShell test alert caught by EDR. Both were expected test activity |
| 19 | Built an Intune attack surface reduction policy (four rules in Block), scoped it to a one-device group, and verified it on the endpoint |
| 20 | Ran Atomic Red Team persistence tests, traced the alerts to raw telemetry, and hunted across three tables |
| 21 | Wrote two hunt hypotheses: scheduled task persistence (T1053.005) and inbox rule hiding (T1564.008) |
| 22 | Ran the hunt. Scheduled task hypothesis partially supported; inbox rule hypothesis untestable because `CloudAppEvents` was empty |
| 23 | Investigated the Day 20 High alert and wrote the report: true positive for the behavior, benign in intent |
| 24 | Reviewed the Entra admin center, focusing on Identity and Protection |
| 25 | Built a block-by-country Conditional Access policy and confirmed it blocked a VPN sign-in from Japan (error 53003) |
| 26 | No assignment. Continued exploring the Entra admin center |
| 27 | Connected Entra ID to Sentinel and confirmed `SigninLogs` and `AuditLogs` with KQL |
| 28 | Final mini project activity: a phishing lure (quarantined), a risky sign-in from Romania, and Mimikatz plus Atomic Red Team T1082 on the endpoint. Attack disruption contained the user and isolated the device |
| 29 | Wrote the Incident 810 report |
| 30 | Wrapped up the challenge. Tore down the lab on October 13 when the trial ended |

---

## Reflection

**What I can do now that I couldn't before.** Stand up Sentinel on Log Analytics, connect data sources into it, query it in KQL, write a scheduled detection with proper entity mapping, and investigate the resulting incident to a documented verdict — without following click-by-click instructions. By the end I could also hunt from a hypothesis with no alert to follow, build and prove an identity control, and write up an incident where automated response acted before I did.

**What was most useful.** Writing a rule and then investigating what it produced, in that order. Building the detection made me decide what "suspicious" meant numerically; investigating the alert showed me what the rule could and couldn't tell me once it fired. Those are two different skills and most tutorials only teach the first.

**What I'd do differently in a real SOC.**

- Check timestamp semantics on any new data source before building time-based dashboards or detections on it. Ingestion time is not event time, and the failure is silent.
- Fix data quality before tuning detections. The 4625 events in this workspace have no source IP, so the brute force couldn't be attributed or blocked — no amount of rule tuning fixes a missing field.
- Clean up or clearly label failed-state resources right away. Leaving `-01` next to `-02` is fine when I'm the only one looking; in a shared environment it's someone querying the wrong workspace and concluding there's no data.
- Treat a zero-row query as unproven, not negative, until I've confirmed the query matches the actual schema.
- Don't rely on filtering alone. A BEC-style lure reached the Inbox with Threat type None on Day 15, and a click-through simulation compromised one of two users, so user reporting and training are the backstop.
- Scope after a user report. A report covers only the message reported, so search for the sender to find every copy.
- Record what I could not determine. The Day 16 report says why there is no URL IOC instead of guessing.
- Verify a control on the endpoint, not only in the portal. Intune said the ASR policy succeeded; `Get-MpPreference` is what showed the four rules enforcing.
- Check more than one telemetry table before concluding something didn't happen. One persistence test showed up only as a process command line.
- Know what automated response can do to my own accounts before running simulations, and where to find and undo it.
- Confirm a table is populated before hunting in it. `CloudAppEvents` was empty, so the inbox rule hypothesis could only be reported as a coverage gap.
- Don't narrow a hunt hypothesis too early. Filtering to user-writable paths would have missed a task that runs `cmd.exe` from System32.
- Review Action Center history after every automated response. Contain user and Isolate device are separate actions, and a Day 20 isolation that fired four minutes after I released the user containment sat in place for nearly a week.
- Treat an antivirus exclusion as temporary and remove it right after the test. It turns off static protection for the whole path.
- Don't disable security defaults without a Conditional Access MFA policy to replace them. The Romania sign-in went through with single-factor authentication.
- Remember that risk-based identity detections need history. A brand-new test account signing in from a new country raised no risk detection.

**What I want to keep improving.** Detection tuning. I can write a rule that fires; deciding a threshold from a baseline rather than from a round number, and measuring the false-positive rate afterward, is the part I want to keep pushing on.

---

## Skills demonstrated

`Microsoft Sentinel` · `Log Analytics` · `KQL` · `Detection engineering` · `Defender XDR` · `Defender for Office 365` · `Microsoft Entra ID` · `Azure resource management` · `Windows Event Log analysis` · `MITRE ATT&CK` · `Incident documentation` · `Microsoft Intune` · `Defender for Endpoint` · `Attack surface reduction` · `Adversary simulation (Atomic Red Team)` · `Advanced hunting` · `Safe Links` · `Anti-phishing policy` · `Attack simulation training` · `Device timeline investigation` · `Threat hunting` · `Conditional Access` · `Entra ID sign-in and audit logs` · `Automatic attack disruption` · `Action Center response actions`

---

*Lab environment only. All telemetry is synthetic or self-generated. The tenant, Azure resources, devices, and test accounts were torn down on October 13, 2026, so any domains, account names, or IP addresses shown here refer to a decommissioned lab.*
