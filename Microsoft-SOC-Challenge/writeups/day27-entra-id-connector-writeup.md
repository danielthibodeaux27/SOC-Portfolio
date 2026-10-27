# Day 27: Entra ID Data Connector in Microsoft Sentinel

**Date:** October 10, 2026 · **Workspace:** `mdf-dt-law-sentinel-02` · **Type:** Data source onboarding and validation

## Findings

- **Connected:** the Microsoft Entra ID data connector, with **Sign-in Logs** and **Audit Logs** selected. The Data connectors page went from the earlier 8 available / 7 connected to **9 available / 8 connected**, with Entra ID showing Connected.
- **Installed first:** the Microsoft Entra ID solution from Content hub (1 data connector, 3 workbooks, 74 analytics rule templates, 1 watchlist, 11 playbooks).
- **Confirmed flowing:** `SigninLogs` returned 3 sign-ins and `AuditLogs` returned 1 policy change, all from telemetry I generated after enabling the connector.

## What I did

1. Installed the Microsoft Entra ID solution from Content hub.
2. Enabled the Entra ID data connector with Sign-in Logs and Audit Logs.
3. Waited for ingestion. Nothing showed up at first, because the connector only forwards events from the moment it's enabled. Older sign-ins are not backfilled.
4. Generated fresh telemetry: a normal sign-in, a sign-in blocked by my Day 25 Conditional Access policy (error 53003), and a policy edit.
5. Ran KQL against `SigninLogs` and `AuditLogs` to confirm everything landed.

![Data connectors: Entra ID connected](../screenshots/day27-01-data-connectors-entra-connected.png)

## Validation queries

**Sign-in logs:** [`entra-signin-logs.kql`](../kql/entra-signin-logs.kql)

| User | App | Location | ResultType | Conditional Access |
|---|---|---|---|---|
| Robert Smith | One Outlook Web | JP | 53003, blocked by Conditional Access | failure |
| Richard Hale | One Outlook Web | US | 50140, "Keep me signed in" interrupt | success |
| My admin account | Office365 Shell | US | 0 | notApplied |

The 53003 row is the Day 25 policy working, now queryable from Sentinel instead of only from the Entra admin center.

![SigninLogs query](../screenshots/day27-02-signinlogs-query.png)

**Audit logs:** [`entra-audit-policy-changes.kql`](../kql/entra-audit-policy-changes.kql)

One row: *Update conditional access policy*, Category Policy, Result success.

![AuditLogs query](../screenshots/day27-03-auditlogs-policy-update.png)

## Limits

Only interactive sign-ins and audit logs were enabled. Non-interactive, service principal, and managed identity sign-ins, and the Identity Protection risk tables (User Risk Events, Risky Users), were left off, so those signals are not in this workspace.
