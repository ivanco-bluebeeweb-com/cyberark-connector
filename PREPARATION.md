# CyberArk Connector — Preparation

**Version:** 0.1.0 (planning)
**Date:** 2026-08-24
**Related task:** BBW Imperal Apps (IAM/Access Management category — CyberArk PAM)
**Scope decision:** maximum feasible capability against the publicly documented
CyberArk Privileged Access Manager REST API (PVWA), per standing "максимальный
функционал" instruction.

## 1. App passport

**Name:** CyberArk Connector
**One-line purpose:** Connect your own CyberArk Privileged Access Manager (PVWA)
to manage Safes, privileged Accounts, credential retrieval/rotation requests,
Just-In-Time access requests, and Applications (AAM), plus review the Security
Events audit trail.

**What it is not:**
- Not CyberArk Identity (the separate SSO/IGA cloud product, formerly Idaptive)
  — that is a distinct product with a distinct API; out of scope for v1.
- Not Endpoint Privilege Manager (EPM) — a separate CyberArk product/API,
  Tier 2/future.
- Not Conjur (secrets management for machines/CI) — separate product surface,
  Tier 2/future.

## 2. Human problem

> A security engineer or PAM administrator running CyberArk needs to onboard a
> new privileged account into a Safe, grant a developer time-boxed access to a
> credential, trigger a manual password rotation after a suspected compromise,
> or review who accessed what and when — without opening the PVWA web client
> for every routine task.

### Personas
| Persona | Trigger | Value |
|---|---|---|
| PAM administrator | New privileged account needs onboarding | create_account inside the right Safe in one call |
| Security engineer | Suspected credential compromise | change_account_password (rotate now) |
| Helpdesk / just-in-time requester | Developer needs temporary access to a credential | create_access_request, then retrieve on approval |
| Security engineer | Investigating suspicious privileged activity | list_security_events filtered by user/safe |
| Safe owner | Wants to see who can access a Safe | list_safe_members |
| Compliance officer | Needs an inventory of privileged accounts | audit_safes — accounts near rotation deadline, safes with no owner |

## 3. Scope tiers

**Tier 1 (this release):**
- connect_cyberark (PVWA base URL + credentials, CyberArk Authentication API
  or LDAP/RADIUS/SAML depending on configured auth method — start with the
  common CyberArk-authenticate flow), disconnect_cyberark, list_connections
- Safes: list_safes, get_safe, create_safe, list_safe_members, add_safe_member
- Accounts: list_accounts, get_account, create_account, update_account,
  delete_account, change_account_password (rotate now),
  verify_account_password, reconcile_account_password
- Credential retrieval: get_account_password (with reason/ticket-id support
  for dual-control Safes)
- Access requests (Just-In-Time / dual control): create_access_request,
  list_access_requests, confirm_access_request, cancel_access_request
- Applications (AAM/CCP identities): list_applications, get_application
- Security Events / audit: list_security_events
- Platforms: list_platforms (the account-type templates CyberArk uses)
- Value-add: audit_safes (accounts overdue for rotation, safes with a single
  owner / no owner, recently failed retrievals)

**Tier 2 (future):**
- Conjur secrets, EPM policies, CyberArk Identity SSO/IGA, Discovery &
  Audit (DNA) scan management, PSM session recording playback.

## 4. Auth model

PVWA's REST API supports several authentication methods (CyberArk native,
LDAP, RADIUS, SAML, Windows). v1 targets **CyberArk Authentication**
(`POST /PasswordVault/API/auth/Cyberark/Logon` with username+password, or
`/RADIUS/Logon`), returning a session token used as `Authorization` header on
all subsequent calls. Token has a configurable idle timeout (default 20 min)
— the connector re-authenticates transparently on 401.

Multi-instance: a user can connect several PVWA installations (e.g. prod +
staging vaults), selected in tool calls the same way every other connector in
this portfolio does it (`connection_id`, defaults to first).

## 5. Safety rules

- `get_account_password` (credential retrieval) and `change_account_password`
  (rotation) are always flagged `action_type="write"` with strong effects
  metadata — retrieving or rotating a live credential is a high-consequence
  action.
- `delete_account` and `delete_safe`-class destructive actions require the
  caller to pass an explicit id; no bulk-delete-by-filter is exposed.
- Dual-control Safes: `get_account_password` surfaces CyberArk's own
  confirmation-required error clearly rather than silently failing, and
  `create_access_request` is the documented way to request the needed
  confirmations first.
