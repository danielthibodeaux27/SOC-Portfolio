# Days 21–22: Hypothesis-Driven Threat Hunting

**Endpoint and tenant:** MDF-DT-W11 and the lab Microsoft 365 tenant · **Lookback:** last 30 days · **Type:** Proactive hunt, no alert to follow

Day 21 was choosing the hypotheses. Day 22 was running them in Advanced Hunting and recording what the data could and could not answer.

## Hypotheses

| | Hypothesis | ATT&CK |
|---|---|---|
| A | If an attacker established persistence on an endpoint, a new scheduled task would appear that runs a binary or script from a user-writable path. | T1053.005 Scheduled Task |
| B | If a user account was phished and accessed by an attacker, the attacker would create an inbox rule that moves or deletes security or reply emails. | T1564.008 Email Hiding Rules |

## Findings

- **Hypothesis A: partially supported.** A new task did appear, but its action was not in a user-writable path, so the second half of the hypothesis did not hold.
- **Hypothesis B: could not be tested.** `CloudAppEvents` had zero rows in 30 days, so Exchange activity was not reaching Advanced Hunting at all.
- **The one task that matters is my own.** `\spawn` from the Day 20 Atomic Red Team test shows the detection path works. It does not show how common this behavior is in a real environment.

## Hypothesis A: scheduled task persistence

Queries: [`scheduled-task-hunt.kql`](../kql/scheduled-task-hunt.kql)

I started broad and narrowed, so I could see exactly where the hypothesis broke.

| Step | Table | Result |
|---|---|---|
| 1. Every task created | `DeviceEvents` (`ScheduledTaskCreated`) | 87 tasks. The newest is `\spawn`, created by `usera` on Oct 5 at 4:06:41 PM. The rows below it are Windows EnterpriseMgmt (Intune enrollment) tasks created by the device account. |
| 2. Filter to user-writable paths (`AppData`, `Temp`, `ProgramData`) | `DeviceEvents` | 0 rows |
| 3. Registry corroboration | `DeviceRegistryEvents` (`TaskCache\Tree`) | 92 keys, all written by `svchost.exe` as SYSTEM |
| 4. How the task was created | `DeviceProcessEvents` (`schtasks.exe /create`) | 1 row: `SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`, launched by `cmd.exe` as `usera` |

**Why step 2 was empty.** `\spawn` runs `C:\windows\system32\cmd.exe`, a living-off-the-land binary in a protected system path. A hunt tuned only to user-writable paths would have missed my own test task.

**What each table contributed.** `DeviceEvents` gave the task name, trigger, and action. `DeviceProcessEvents` gave the command line and parent process, which is how the task was made and by whom. `DeviceRegistryEvents` confirms the task exists, but every key is written by `svchost.exe` as SYSTEM, so the registry can't tell you who created a task.

![All scheduled task creations, 87 rows](../screenshots/day22-01-all-scheduled-tasks.png)

![How the task was created: schtasks.exe command line](../screenshots/day22-05-schtasks-process-events.png)

## Hypothesis B: inbox rule hiding

Query: [`cloudappevents-coverage.kql`](../kql/cloudappevents-coverage.kql)

Before writing any inbox rule query, I checked whether the table had data at all. `CloudAppEvents | take 10` returned nothing over 30 days. The table was empty, not merely free of inbox rule events, so this is a finding about logging coverage, not about attacker behavior.

![CloudAppEvents empty over 30 days](../screenshots/day22-06-cloudappevents-coverage.png)

**What it would take to test it:**

- **Data:** Exchange mailbox audit events in `CloudAppEvents` (Microsoft 365 app connector in Defender for Cloud Apps) or in Sentinel's `OfficeActivity` table (Office 365 connector).
- **Activity:** with the connector confirmed on, an inbox rule created in Outlook on the web by a lab user, then the query rerun after the ingestion delay.
- **Better tooling:** Defender for Cloud Apps anomaly detection for suspicious inbox manipulation rules is a stronger control than a hunting query.

## What would separate benign from malicious

| Question | Benign predicts | Malicious predicts |
|---|---|---|
| Task action | A signed vendor binary in Program Files | `cmd.exe`, `powershell.exe`, or a script, often with encoded arguments |
| Task creator | SYSTEM or the device account during enrollment or updates | An interactive user account in an elevated session |
| Inbox rule actions | Move newsletters to a folder | Delete, mark as read, or forward externally, keyed on words like "invoice" or "password" |
| Rule source IP | Known location and device | First-seen IP, hosting or VPN provider, shortly after a phishing click |

## Recommendations

1. Hunt scheduled task creation by interactive accounts, not only tasks in user-writable paths. LOLBins in system paths defeat the path filter.
2. Use `DeviceProcessEvents` for attribution. The registry shows that a task exists, not who made it.
3. Confirm a table is populated before reporting a negative. A zero-row result from an empty table says nothing about the hypothesis.
4. Enable Exchange mailbox audit ingestion before relying on inbox rule detections.

## Limits

The only interesting task in the data is one I created myself, so this shows the detection works, not how often the behavior occurs. Hypothesis B was not tested at all.
