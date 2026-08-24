# CyberArk Connector — UI Component Plan

Source: `UI_COMPONENT_VOCABULARY.md` + `~/UI_INTERFACE_STANDARD.md`. Only
primitives from the verified vocabulary are used below.

## Standing rules applied (binding for every screen in this plan)
- Every input carries its own visible label (`Text(variant="caption")` above
  the input), never a bare placeholder.
- Placeholders are contextually specific to the exact field (e.g. a realistic
  PVWA URL shape), never generic.
- The connect form container is stretched to the full width of the left
  sidebar; its own contents (inputs, selects, buttons) stretch to fill it
  (`align="stretch"`).
- The sidebar carries NO instructions duplicated from the "How do I get this?"
  modal — the modal is the only place with the credential-setup walkthrough.
- No `Card` (decorated box) anywhere in the left sidebar — plain `Stack` +
  `Divider` only.

## 1. Left sidebar (`slot="left"`)

**Not connected:**
- `Button` "How do I get this?" (ghost, opens `cyberark_connect_help` modal)
- `Form(action="connect_cyberark")`:
  - Auth method `Select` (CyberArk / RADIUS) — first field
  - PVWA base URL `Input` (placeholder: a realistic `https://pvwa.acme.com/PasswordVault` shape)
  - Username `Input`
  - Password `Input` (masked)
  - Submit button "Connect"

**Connected (one or more vaults):**
- `Text` vault label, `Divider`
- `Button` list (ghost, full width, left-aligned) opening each center panel:
  Safes, Accounts, Access Requests, Applications, Platforms, Security Events
- `Divider`
- `Button` "App settings" (secondary, always last)

## 2. Center panels (`slot="center"`, `center_overlay=True`)

- `cyberark_safes` — `DataTable` (safe name, description, member count) or `Empty`
- `cyberark_accounts` — `DataTable` (name, safe, platform, username, last change) or `Empty`
- `cyberark_access_requests` — `DataTable` (account, requestor, status, reason) or `Empty`
- `cyberark_applications` — `DataTable` (app id, description, disabled) or `Empty`
- `cyberark_platforms` — `DataTable` (platform id, name, active) or `Empty`
- `cyberark_security_events` — `DataTable` (timestamp, user, action, safe) or `Empty`
- `cyberark_connect_help` — modal: numbered walkthrough for creating a PVWA
  user with API access + minimum required Safe permissions
- `cyberark_settings` — connected-vaults list, each with a "Disconnect"
  (destructive) button

## 3. Confirmation modals (destructive/high-consequence actions)

- Before `get_account_password`: modal "You are about to retrieve a live
  privileged credential. This is logged in CyberArk's own audit trail." +
  reason/ticket-id input if the Safe requires dual control.
- Before `change_account_password` / `reconcile_account_password`: modal
  "This will change the real password on the target system right now."
- Before `delete_account` / `delete_safe`: standard destructive-confirm modal,
  explicit id shown, no bulk variant exposed.

## 4. User flow (given the component constraints above)

1. Land on app → left sidebar shows connect form (not connected) or nav list
   (connected).
2. Connect → session token verified live against `GET /Safes?limit=1` →
   sidebar switches to nav list, center shows a `cyberark_overview` health
   snapshot (via `audit_safes`) as the default landing panel.
3. Click "Accounts" → center panel loads `list_accounts` for the selected
   vault → user can drill into one row's actions via row-level buttons
   (Retrieve / Rotate / Verify / Reconcile) — each destructive/sensitive one
   gated by its confirmation modal.
4. Click "Access Requests" → shows pending dual-control requests; approver can
   confirm or cancel from this panel.
5. "App settings" → manage connected vaults, disconnect one.
