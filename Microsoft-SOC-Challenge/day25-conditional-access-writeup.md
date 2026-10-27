# Day 25: Conditional Access — Block Sign-ins by Country

**Date:** October 8, 2026 · **Tenant:** lab Microsoft 365 E5 trial · **Test user:** richard.hale · **Type:** Identity control build and validation

Times are UTC, as shown in the Entra sign-in logs.

## Findings

- **Control built:** Conditional Access policy `mdf-dt-ca-block-country-01`, set to **On**, blocking access to all resources for the included users when the sign-in comes from named location `mdf-dt-nl-blocked-countries-01` (Japan).
- **Prerequisite:** Entra security defaults had to be disabled before Conditional Access policies could be enabled. I chose "My organization is planning to use Conditional Access" as the reason.
- **Validation:** a sign-in as richard.hale through a VPN exit in Tokyo was blocked. The user saw *You cannot access this right now*, and the sign-in log recorded **Failure, error 53003**, with the policy result **Block / Failure**.
- **Decision:** I left the policy On afterward, with security defaults still disabled.

## Build

| Setting | Value |
|---|---|
| Named location | `mdf-dt-nl-blocked-countries-01`, Countries location, Japan |
| Country lookup | Determine location by IP address (IPv4 and IPv6) |
| Unknown countries/regions | Not included |
| Policy | `mdf-dt-ca-block-country-01` |
| Users | Specific users included |
| Target resources | All resources (formerly "All cloud apps") |
| Network | 1 included (the named location) |
| Grant | Block access |
| State | On |

Japan was chosen because it was the VPN exit I could test from. In a real tenant the list comes from where the business does not operate.

![Named location: Japan](../screenshots/day25-03-named-location-japan.png)

![Conditional Access policy](../screenshots/day25-04-ca-policy-block-country.png)

## Validation

1. Connected the VPN and confirmed the exit IP geolocated to Tokyo, Japan (187.15.136.107).
2. Signed in to Outlook on the web as richard.hale.
3. Checked the sign-in log for the result and the policy that applied.

| Time (UTC) | Source | Status | Conditional Access |
|---|---|---|---|
| 2026-10-08 15:47:41 | Home network (baseline) | Success | Not applied |
| 2026-10-08 18:19:32 | 187.15.136.107 (Tokyo VPN) | Interrupted | Not applied |
| 2026-10-08 19:39:11 | VPN | **Failure, 53003** | `mdf-dt-ca-block-country-01`: Block, Failure |

The 19:39:11 sign-in's failure reason reads *Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.* Authentication requirement was single-factor.

![Block page shown to the user](../screenshots/day25-07-signin-blocked-page.png)

![Sign-in details: error 53003](../screenshots/day25-09-signin-error-53003.png)

## What this means for an investigation

- **53003** in `SigninLogs` (`ResultType`) is the code to search for Conditional Access blocks. The Conditional access tab names the exact policy, which matters once a tenant has several.
- The block page tells the user their sign-in *was successful* but did not meet the criteria. Conditional Access is evaluated after the first factor, so the credentials worked and the policy stopped the token. Repeated 53003 failures from a blocked country likely mean someone else has the password.

## Recommendations

1. Disabling security defaults removes their MFA baseline. Replace it with a Conditional Access policy that requires MFA before turning security defaults off in a production tenant.
2. A country block only covers the countries listed. On Day 28 a sign-in from Romania was allowed with single-factor authentication: Romania was not on the list, and the missing MFA challenge is consistent with security defaults being off.
3. Roll new policies out in Report-only first, and exclude a break-glass admin account so a mistake can't lock out every administrator.

## Limits

The policy targets specific test users, not all users, and the named location contains one country. The 18:19:32 sign-in shows Not applied, and I did not determine whether that sign-in came before the policy was enabled.
