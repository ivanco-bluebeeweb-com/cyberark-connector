# CyberArk Connector — Connector Discovery

**Discovery date:** 2026-08-24
**Release scope:** maximum functionality against the publicly documented
CyberArk Privileged Access Manager REST API (PVWA).
**Related task:** BBW Imperal Apps (IAM/Access Management category).

## 1. What CyberArk actually is

CyberArk is the market leader in Privileged Access Management (PAM) — it
secures, rotates, and audits access to privileged credentials (admin
passwords, SSH keys, API keys) stored in "Safes" inside a hardened Digital
Vault. Its REST surface is the **PVWA (Password Vault Web Access) REST API**,
served at `https://{pvwa-host}/PasswordVault/API/*`, alongside the older
"WebServices" SOAP/REST hybrid (superseded by the current REST API for new
integrations).

## 2. Chosen integration surface

**PVWA REST API** (`/PasswordVault/API/*`):
- Authentication (`/auth/Cyberark/Logon`, `/auth/Cyberark/Logoff`) — session
  token issuance/revocation.
- Safes (`/Safes`) — list, get, create, list members, add member.
- Accounts (`/Accounts`) — list (with rich search filters), get, create,
  update, delete.
- Account actions (`/Accounts/{id}/Password/*`) — Retrieve (get password),
  Change (rotate immediately), Verify (check it still matches the target),
  Reconcile (force-sync using the reconciliation account).
- Access requests / dual control (`/Accounts/{id}/Requests`) — for Safes
  configured to require confirmation before retrieval: create, list, confirm,
  cancel a request.
- Applications (`/Applications`) — AAM/CCP application identities that can
  fetch credentials programmatically — list, get.
- Platforms (`/Platforms`) — account-type templates (e.g. "WinServerLocal",
  "UnixSSH") required when creating an account.
- Security Events (`/API/reports` or the audit event stream depending on
  version) — exposed here as `list_security_events`, best-effort against the
  documented reporting endpoints since CyberArk's audit API varies more by
  version than other resources.

Not in scope for v1 (Tier 2/future): Conjur (separate product/API for
machine/CI secrets), Endpoint Privilege Manager, CyberArk Identity
(SSO/lifecycle — a distinct cloud product), Discovery & Audit (DNA) scanning,
PSM session recording playback.

## 3. Auth model

CyberArk Authentication (`POST /PasswordVault/API/auth/Cyberark/Logon`) with
`{username, password, concurrentSession: true}` → returns a raw session token
string used as the value of the `Authorization` header on every subsequent
call (no `Bearer` prefix — PVWA's own convention). Token idle-expires
(commonly 20 minutes); the connector transparently re-authenticates on a 401.

LDAP/RADIUS/SAML/Windows authentication exist as alternate PVWA logon
endpoints (`/auth/LDAP/Logon`, `/auth/RADIUS/Logon`, `/auth/SAML/Logon`) —
v1 supports CyberArk-native and RADIUS (both are simple credential-based
POSTs); SAML requires a browser redirect flow out of scope for a
non-interactive connector.

Multi-vault: several PVWA instances (e.g. prod + DR vault) can be connected
side by side, selected via `connection_id` the same way every other connector
in this portfolio does it.

## 4. Safety rules

- `get_account_password` (credential retrieval) and `change_account_password`
  / `reconcile_account_password` (rotation) are the two highest-consequence
  actions in this connector — always `action_type="write"` with explicit
  `effects` metadata so downstream audit tooling can flag them distinctly
  from routine reads.
- `delete_account` and `delete_safe` require an explicit id per call; no
  bulk-delete-by-filter is exposed, matching this portfolio's standing rule
  against blast-radius footguns.
- Dual-control Safes: CyberArk itself returns a specific error
  (`PASWS004E`/similar) when retrieval needs prior confirmation — the
  connector surfaces that message verbatim rather than masking it, and
  documents `create_access_request` as the correct next step.
