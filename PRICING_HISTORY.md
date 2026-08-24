# Pricing History — CyberArk Connector

## Known platform quirk: first `save_pricing` call silently fails

**Symptom:** the first `developer__save_pricing` call for `cyberark-connector`
returned an error saying the model was stored as `'free'` (not the requested
`'per_action'`) and every `tool_prices` key was "not stored" — despite the
API raising no error and the payload being well-formed.

**Fix:** retried the exact same call with an identical payload. It succeeded
fully the second time (pricing_model confirmed `per_action`, manifest_json
populated with prices).

This is the same pattern already seen and documented on Okta Connector,
Ping Identity Connector, MuleSoft Connector, and Asana Connector. Root cause
is platform-side (a caching/propagation lag between the pricing write and
the read-back verification), not a client error. **Standing fix for every
future app: if `save_pricing` reports a mismatch with no underlying API
error, retry once with the identical payload before treating it as a real
failure.**

## Final pricing (per_action model)

| Action | Price (tokens) |
|---|---|
| connect_cyberark | 0 (free) |
| disconnect_cyberark | 0 (free) |
| list_connections | 0 (free) |
| get_safe | 10 |
| list_safe_members | 10 |
| list_safes | 10 |
| get_account | 15 |
| get_application | 15 |
| list_access_requests | 15 |
| list_accounts | 15 |
| list_applications | 15 |
| list_platforms | 15 |
| cancel_access_request | 20 |
| audit_vault | 30 |
| add_safe_member | 30 |
| confirm_access_request | 30 |
| delete_account | 30 |
| update_account | 30 |
| list_security_events | 25 |
| create_access_request | 40 |
| create_safe | 40 |
| verify_account_password | 40 |
| create_account | 50 |
| reconcile_account_password | 60 |
| change_account_password | 70 |
| retrieve_account_password | 80 |

Read/list operations priced lowest; credential-exposing and mutation actions
(especially `retrieve_account_password`, `change_account_password`,
`reconcile_account_password`) priced highest, reflecting their sensitivity
and the real operational risk they carry on the target vault.
