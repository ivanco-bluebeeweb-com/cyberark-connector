"""Chat functions for CyberArk Connector (PVWA REST API)."""
from __future__ import annotations

import json
import uuid

from imperal_sdk import ActionResult

import cyberark_client as cc
from app import chat
from schemas import (
    AccessRequest, AccessRequestIdParams, AccessRequestList, AccountIdParams,
    AccountList, ApplicationIdParams, ApplicationList, ChangePasswordParams,
    ConnectCyberArkParams, ConnectionList, ConnectionRefParams,
    CreateAccessRequestParams, CreateAccountParams, CreateSafeParams,
    CyberArkAccount, CyberArkApplication, CyberArkConnection, CyberArkPlatform,
    CyberArkSafe, DeleteResult, DisconnectCyberArkParams, HealthAudit,
    ListAccessRequestsParams, ListAccountsParams, ListApplicationsParams,
    ListPlatformsParams, ListSafesParams, ListSecurityEventsParams,
    PlatformList, RetrievePasswordParams, RetrievedPassword, SafeIdParams,
    SafeList, SafeMember, SafeMemberList, SafeMemberParams,
    SecurityEvent, SecurityEventList, UpdateAccountParams,
)

_SECRET_NAME = "cyberark_connections"


async def _load_connections(ctx) -> list[dict]:
    raw = await ctx.secrets.get(_SECRET_NAME)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []


async def _save_connections(ctx, connections: list[dict]) -> None:
    await ctx.secrets.set(_SECRET_NAME, json.dumps(connections))


def _connection_entity(c: dict) -> CyberArkConnection:
    return CyberArkConnection(
        connection_id=c.get("id", ""),
        label=c.get("label") or c.get("base_url", ""),
        base_url=c.get("base_url", ""),
        auth_method=c.get("auth_method", "cyberark"),
    )


async def _resolve_connection(ctx, connection_id: str) -> dict:
    connections = await _load_connections(ctx)
    if not connections:
        raise RuntimeError("No CyberArk vault connected yet. Use connect_cyberark first.")
    if connection_id:
        for c in connections:
            if c.get("id") == connection_id:
                return c
        raise RuntimeError(f"No CyberArk connection found with id '{connection_id}'.")
    return connections[0]


def _client_for(c: dict) -> cc.CyberArkClient:
    return cc.CyberArkClient(
        base_url=c.get("base_url", ""),
        username=c.get("username", ""),
        password=c.get("password", ""),
        auth_method=c.get("auth_method", "cyberark"),
    )


@chat.function("connect_cyberark", "Connect your own CyberArk PVWA vault by saving its base URL and credentials, after checking they actually work.", action_type="write", chain_callable=True, data_model=CyberArkConnection, event="cyberark-connector.connect_cyberark", effects=["cyberark.provider.connected"])
async def connect_cyberark(ctx, params: ConnectCyberArkParams) -> ActionResult:
    """Connect your own CyberArk PVWA vault by saving its base URL and credentials, after checking they actually work."""
    client = cc.CyberArkClient(params.base_url, params.username, params.password, params.auth_method)
    await client._logon()  # raises CyberArkError with a clean message on failure
    connections = await _load_connections(ctx)
    entry = {
        "id": str(uuid.uuid4()),
        "label": params.label or params.base_url,
        "base_url": client.base_url.removesuffix("/API"),
        "auth_method": params.auth_method,
        "username": params.username,
        "password": params.password,
    }
    connections.append(entry)
    await _save_connections(ctx, connections)
    return ActionResult(data=_connection_entity(entry), message=f"Connected to CyberArk vault '{entry['label']}'.")


@chat.function("disconnect_cyberark", "Disconnect a CyberArk vault: deletes only the saved credentials. Nothing in CyberArk itself is changed.", action_type="write", chain_callable=True, data_model=DeleteResult, event="cyberark-connector.disconnect_cyberark", effects=["cyberark.provider.disconnected"])
async def disconnect_cyberark(ctx, params: DisconnectCyberArkParams) -> ActionResult:
    """Disconnect a CyberArk vault: deletes only the saved credentials. Nothing in CyberArk itself is changed."""
    connections = await _load_connections(ctx)
    remaining = [c for c in connections if c.get("id") != params.connection_id]
    if len(remaining) == len(connections):
        raise RuntimeError(f"No CyberArk connection found with id '{params.connection_id}'.")
    await _save_connections(ctx, remaining)
    return ActionResult(data=DeleteResult(ok=True, detail=params.connection_id), message="Disconnected from CyberArk.")


@chat.function("list_connections", "List the connected CyberArk vaults.", action_type="read", chain_callable=True, data_model=ConnectionList, event="cyberark-connector.list_connections")
async def list_connections(ctx, params: NoParams) -> ActionResult:
    """List the connected CyberArk vaults."""
    connections = await _load_connections(ctx)
    return ActionResult(data=ConnectionList(connections=[_connection_entity(c) for c in connections]))


@chat.function("audit_vault", "Build one aggregated health report for the connected CyberArk vault: Safe count, Account count, and pending access requests.", action_type="read", chain_callable=True, data_model=HealthAudit, event="cyberark-connector.audit_vault")
async def audit_vault(ctx, params: ConnectionRefParams) -> ActionResult:
    """Build one aggregated health report for the connected CyberArk vault: Safe count, Account count, and pending access requests."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    safes, _ = await client.request("GET", "/Safes", params={"limit": 1000})
    accounts, _ = await client.request("GET", "/Accounts", params={"limit": 1000})
    safe_items = (safes or {}).get("value", [])
    account_items = (accounts or {}).get("value", [])
    safe_count = len(safe_items)
    account_count = (accounts or {}).get("count", len(account_items))
    overdue = 0
    for a in account_items:
        sm = a.get("secretManagement", {}) or {}
        if sm.get("automaticManagementEnabled") is False or sm.get("status") == "failure":
            overdue += 1
    findings = []
    if overdue:
        findings.append(f"{overdue} account(s) have automatic management disabled or a failed last rotation.")
    if safe_count == 0:
        findings.append("No Safes visible to this API user -- check its Safe permissions.")
    return ActionResult(data=HealthAudit(
        safe_count=safe_count,
        account_count=account_count,
        accounts_overdue_rotation=overdue,
        safes_without_owner=0,
        findings=findings,
    ))


@chat.function("list_safes", "List Safes in the connected CyberArk vault, optionally filtered by a search string.", action_type="read", chain_callable=True, data_model=SafeList, event="cyberark-connector.list_safes")
async def list_safes(ctx, params: ListSafesParams) -> ActionResult:
    """List Safes in the connected CyberArk vault, optionally filtered by a search string."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    q: dict = {"limit": params.limit}
    if params.search:
        q["search"] = params.search
    data, _ = await client.request("GET", "/Safes", params=q)
    items = (data or {}).get("value", [])
    safes = [CyberArkSafe(
        safe_name=s.get("safeName", ""), description=s.get("description", ""),
        member_count=s.get("numberOfDaysRetention", 0), managing_cpm=s.get("managingCPM", ""),
    ) for s in items]
    return ActionResult(data=SafeList(safes=safes))


@chat.function("get_safe", "Read one CyberArk Safe in full.", action_type="read", chain_callable=True, data_model=CyberArkSafe, event="cyberark-connector.get_safe")
async def get_safe(ctx, params: SafeIdParams) -> ActionResult:
    """Read one CyberArk Safe in full."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    s, _ = await client.request("GET", f"/Safes/{params.safe_name}")
    return ActionResult(data=CyberArkSafe(
        safe_name=s.get("safeName", ""), description=s.get("description", ""),
        member_count=s.get("numberOfDaysRetention", 0), managing_cpm=s.get("managingCPM", ""),
    ))


@chat.function("create_safe", "Create a new Safe in the connected CyberArk vault.", action_type="write", chain_callable=True, data_model=CyberArkSafe, event="cyberark-connector.create_safe", effects=["cyberark.safe.created"])
async def create_safe(ctx, params: CreateSafeParams) -> ActionResult:
    """Create a new Safe in the connected CyberArk vault."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    body = {"SafeName": params.safe_name, "Description": params.description}
    if params.managing_cpm:
        body["ManagingCPM"] = params.managing_cpm
    s, _ = await client.request("POST", "/Safes", json=body)
    return ActionResult(data=CyberArkSafe(
        safe_name=s.get("safeName", params.safe_name), description=s.get("description", params.description),
        member_count=0, managing_cpm=s.get("managingCPM", ""),
    ), message=f"Safe '{params.safe_name}' created.")


@chat.function("list_safe_members", "List the members (users/groups with access) of a CyberArk Safe.", action_type="read", chain_callable=True, data_model=SafeMemberList, event="cyberark-connector.list_safe_members")
async def list_safe_members(ctx, params: SafeIdParams) -> ActionResult:
    """List the members (users/groups with access) of a CyberArk Safe."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    data, _ = await client.request("GET", f"/Safes/{params.safe_name}/Members")
    items = (data or {}).get("value", [])
    members = [SafeMember(
        member_name=m.get("memberName", ""), member_type=m.get("memberType", ""),
        permissions=m.get("permissions", {}),
    ) for m in items]
    return ActionResult(data=SafeMemberList(members=members))


@chat.function("add_safe_member", "Grant a user or group access to a CyberArk Safe.", action_type="write", chain_callable=True, data_model=SafeMember, event="cyberark-connector.add_safe_member", effects=["cyberark.safe.member_added"])
async def add_safe_member(ctx, params: SafeMemberParams) -> ActionResult:
    """Grant a user or group access to a CyberArk Safe."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    body = {"memberName": params.member_name, "searchIn": "Vault", "membershipExpirationDate": None,
            "permissions": {"useAccounts": True, "retrieveAccounts": True, "listAccounts": True}}
    m, _ = await client.request("POST", f"/Safes/{params.safe_name}/Members", json=body)
    return ActionResult(data=SafeMember(
        member_name=m.get("memberName", params.member_name), member_type=m.get("memberType", ""),
        permissions=m.get("permissions", {}),
    ), message=f"'{params.member_name}' added to Safe '{params.safe_name}'.")


@chat.function("list_accounts", "List privileged Accounts in the connected CyberArk vault, optionally filtered by a search string or Safe name.", action_type="read", chain_callable=True, data_model=AccountList, event="cyberark-connector.list_accounts")
async def list_accounts(ctx, params: ListAccountsParams) -> ActionResult:
    """List privileged Accounts in the connected CyberArk vault, optionally filtered by a search string or Safe name."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    q: dict = {"limit": params.limit}
    if params.search:
        q["search"] = params.search
    if params.safe_name:
        q["filter"] = f"safeName eq {params.safe_name}"
    data, _ = await client.request("GET", "/Accounts", params=q)
    items = (data or {}).get("value", [])
    accounts = [_account_entity(a) for a in items]
    return ActionResult(data=AccountList(accounts=accounts))


def _account_entity(a: dict) -> CyberArkAccount:
    return CyberArkAccount(
        account_id=a.get("id", ""), name=a.get("name", ""), safe_name=a.get("safeName", ""),
        platform_id=a.get("platformId", ""), username=a.get("userName", ""), address=a.get("address", ""),
        last_success_change=str(a.get("secretManagement", {}).get("lastModifiedTime", "")),
    )


@chat.function("get_account", "Read one privileged Account's metadata in full (never the secret itself -- use retrieve_account_password for that).", action_type="read", chain_callable=True, data_model=CyberArkAccount, event="cyberark-connector.get_account")
async def get_account(ctx, params: AccountIdParams) -> ActionResult:
    """Read one privileged Account's metadata in full (never the secret itself -- use retrieve_account_password for that)."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    a, _ = await client.request("GET", f"/Accounts/{params.account_id}")
    return ActionResult(data=_account_entity(a))


@chat.function("create_account", "Onboard a new privileged Account into a Safe.", action_type="write", chain_callable=True, data_model=CyberArkAccount, event="cyberark-connector.create_account", effects=["cyberark.account.created"])
async def create_account(ctx, params: CreateAccountParams) -> ActionResult:
    """Onboard a new privileged Account into a Safe."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    body: dict = {
        "safeName": params.safe_name, "platformId": params.platform_id,
        "address": params.address, "userName": params.username,
    }
    if params.name:
        body["name"] = params.name
    if params.secret:
        body["secret"] = params.secret
    a, _ = await client.request("POST", "/Accounts", json=body)
    return ActionResult(data=_account_entity(a), message=f"Account '{a.get('userName', params.username)}' onboarded into Safe '{params.safe_name}'.")


@chat.function("update_account", "Update selected fields of an existing Account (name, address). Only given fields change.", action_type="write", chain_callable=True, data_model=CyberArkAccount, event="cyberark-connector.update_account", effects=["cyberark.account.updated"])
async def update_account(ctx, params: UpdateAccountParams) -> ActionResult:
    """Update selected fields of an existing Account (name, address). Only given fields change."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    ops = []
    if params.name:
        ops.append({"op": "replace", "path": "/name", "value": params.name})
    if params.address:
        ops.append({"op": "replace", "path": "/address", "value": params.address})
    if not ops:
        raise RuntimeError("Provide at least one field to update (name or address).")
    a, _ = await client.request("PATCH", f"/Accounts/{params.account_id}", json=ops)
    return ActionResult(data=_account_entity(a), message="Account updated.")


@chat.function("delete_account", "Permanently delete a privileged Account from CyberArk. Cannot be undone.", action_type="write", chain_callable=True, data_model=DeleteResult, event="cyberark-connector.delete_account", effects=["cyberark.account.deleted"])
async def delete_account(ctx, params: AccountIdParams) -> ActionResult:
    """Permanently delete a privileged Account from CyberArk. Cannot be undone."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    await client.request("DELETE", f"/Accounts/{params.account_id}")
    return ActionResult(data=DeleteResult(ok=True, detail=params.account_id), message="Account deleted.")


@chat.function("retrieve_account_password", "Retrieve a privileged Account's current password/secret. This exposes real credentials -- use with care.", action_type="write", chain_callable=True, data_model=RetrievedPassword, event="cyberark-connector.retrieve_account_password", effects=["cyberark.account.password_retrieved"])
async def retrieve_account_password(ctx, params: RetrievePasswordParams) -> ActionResult:
    """Retrieve a privileged Account's current password/secret. This exposes real credentials -- use with care."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    body = {"Reason": params.reason} if params.reason else {}
    secret, _ = await client.request("POST", f"/Accounts/{params.account_id}/Password/Retrieve", json=body)
    value = secret if isinstance(secret, str) else str(secret)
    return ActionResult(data=RetrievedPassword(account_id=params.account_id, password=value), message="Password retrieved. Handle it as a live secret.")


@chat.function("verify_account_password", "Verify a privileged Account's stored password still matches the target system (CyberArk's own reconciliation check).", action_type="write", chain_callable=True, data_model=DeleteResult, event="cyberark-connector.verify_account_password", effects=["cyberark.account.password_verified"])
async def verify_account_password(ctx, params: AccountIdParams) -> ActionResult:
    """Verify a privileged Account's stored password still matches the target system (CyberArk's own reconciliation check)."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    await client.request("POST", f"/Accounts/{params.account_id}/Verify")
    return ActionResult(data=DeleteResult(ok=True, detail=params.account_id), message="Verification requested. CyberArk's CPM will confirm the credential asynchronously.")


@chat.function("reconcile_account_password", "Force-reconcile a privileged Account's password using its Safe's configured reconciliation account -- use after a manual out-of-band change desynced the vault.", action_type="write", chain_callable=True, data_model=DeleteResult, event="cyberark-connector.reconcile_account_password", effects=["cyberark.account.password_reconciled"])
async def reconcile_account_password(ctx, params: AccountIdParams) -> ActionResult:
    """Force-reconcile a privileged Account's password using its Safe's configured reconciliation account -- use after a manual out-of-band change desynced the vault."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    await client.request("POST", f"/Accounts/{params.account_id}/Reconcile")
    return ActionResult(data=DeleteResult(ok=True, detail=params.account_id), message="Reconciliation requested. CyberArk's CPM will process it asynchronously.")


@chat.function("change_account_password", "Rotate a privileged Account's password immediately (CPM-managed or explicit new value). This changes the real credential in the target system.", action_type="write", chain_callable=True, data_model=DeleteResult, event="cyberark-connector.change_account_password", effects=["cyberark.account.password_changed"])
async def change_account_password(ctx, params: ChangePasswordParams) -> ActionResult:
    """Rotate a privileged Account's password immediately (CPM-managed or explicit new value). This changes the real credential in the target system."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    body = {"ChangeImmediately": True}
    if params.new_password:
        body["NewCredentials"] = params.new_password
    await client.request("POST", f"/Accounts/{params.account_id}/Change", json=body)
    return ActionResult(data=DeleteResult(ok=True, detail=params.account_id), message="Password rotation requested. CyberArk's CPM will apply it on the target system shortly.")


@chat.function("create_access_request", "Create a Just-In-Time access request for a privileged Account -- for Safes configured with dual control, this must be confirmed before retrieval succeeds.", action_type="write", chain_callable=True, data_model=AccessRequest, event="cyberark-connector.create_access_request", effects=["cyberark.access_request.created"])
async def create_access_request(ctx, params: CreateAccessRequestParams) -> ActionResult:
    """Create a Just-In-Time access request for a privileged Account -- for Safes configured with dual control, this must be confirmed before retrieval succeeds."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    body: dict = {"Reason": params.reason, "MultipleAccessRequired": params.multiple_access}
    if params.access_from:
        body["AccessFrom"] = params.access_from
    if params.access_to:
        body["AccessTo"] = params.access_to
    data, _ = await client.request("POST", f"/Accounts/{params.account_id}/Requests", json=body)
    return ActionResult(data=_access_request_entity(data or {}, params.account_id), message="Access request created.")


def _access_request_entity(r: dict, account_id: str) -> AccessRequest:
    return AccessRequest(
        request_id=str(r.get("RequestID", r.get("id", ""))), account_id=account_id,
        status=r.get("Status", r.get("status", "pending")), reason=r.get("Reason", ""),
    )


@chat.function("list_access_requests", "List Just-In-Time access requests for a privileged Account.", action_type="read", chain_callable=True, data_model=AccessRequestList, event="cyberark-connector.list_access_requests")
async def list_access_requests(ctx, params: ListAccessRequestsParams) -> ActionResult:
    """List Just-In-Time access requests for a privileged Account."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    data, _ = await client.request("GET", f"/Accounts/{params.account_id}/Requests")
    items = (data or {}).get("value", data if isinstance(data, list) else [])
    requests = [_access_request_entity(r, params.account_id) for r in items]
    return ActionResult(data=AccessRequestList(requests=requests))


@chat.function("confirm_access_request", "Confirm a pending Just-In-Time access request on a dual-control Safe -- required from a second approver before the requestor can retrieve the credential.", action_type="write", chain_callable=True, data_model=DeleteResult, event="cyberark-connector.confirm_access_request", effects=["cyberark.access_request.confirmed"])
async def confirm_access_request(ctx, params: AccessRequestIdParams) -> ActionResult:
    """Confirm a pending Just-In-Time access request on a dual-control Safe -- required from a second approver before the requestor can retrieve the credential."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    await client.request("POST", f"/Requests/{params.request_id}/Confirm")
    return ActionResult(data=DeleteResult(ok=True, detail=params.request_id), message="Access request confirmed.")


@chat.function("cancel_access_request", "Cancel a pending Just-In-Time access request before it is confirmed or used.", action_type="write", chain_callable=True, data_model=DeleteResult, event="cyberark-connector.cancel_access_request", effects=["cyberark.access_request.cancelled"])
async def cancel_access_request(ctx, params: AccessRequestIdParams) -> ActionResult:
    """Cancel a pending Just-In-Time access request before it is confirmed or used."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    await client.request("DELETE", f"/Requests/{params.request_id}")
    return ActionResult(data=DeleteResult(ok=True, detail=params.request_id), message="Access request cancelled.")


@chat.function("list_applications", "List AAM/CCP Application identities configured on the connected CyberArk vault -- the programmatic identities that can fetch credentials without a human.", action_type="read", chain_callable=True, data_model=ApplicationList, event="cyberark-connector.list_applications")
async def list_applications(ctx, params: ListApplicationsParams) -> ActionResult:
    """List AAM/CCP Application identities configured on the connected CyberArk vault -- the programmatic identities that can fetch credentials without a human."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    data, _ = await client.request("GET", "/Applications")
    items = (data or {}).get("application", data if isinstance(data, list) else [])
    apps = [CyberArkApplication(app_id=a.get("AppID", a.get("appId", "")), description=a.get("Description", ""), disabled=a.get("Disabled", False)) for a in items]
    return ActionResult(data=ApplicationList(applications=apps))


@chat.function("get_application", "Read one AAM/CCP Application identity in full.", action_type="read", chain_callable=True, data_model=CyberArkApplication, event="cyberark-connector.get_application")
async def get_application(ctx, params: ApplicationIdParams) -> ActionResult:
    """Read one AAM/CCP Application identity in full."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    data, _ = await client.request("GET", f"/Applications/{params.app_id}")
    a = data or {}
    return ActionResult(data=CyberArkApplication(app_id=a.get("AppID", params.app_id), description=a.get("Description", ""), disabled=a.get("Disabled", False)))


@chat.function("list_platforms", "List account-type Platforms (templates) configured on the connected CyberArk vault, e.g. 'WinServerLocal', 'UnixSSH' -- required when onboarding a new Account.", action_type="read", chain_callable=True, data_model=PlatformList, event="cyberark-connector.list_platforms")
async def list_platforms(ctx, params: ListPlatformsParams) -> ActionResult:
    """List account-type Platforms (templates) configured on the connected CyberArk vault, e.g. 'WinServerLocal', 'UnixSSH' -- required when onboarding a new Account."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    q = {"active": "true"} if params.active_only else {}
    data, _ = await client.request("GET", "/Platforms", params=q)
    items = (data or {}).get("Platforms", data if isinstance(data, list) else [])
    platforms = [
        CyberArkPlatform(
            platform_id=p.get("PlatformID", p.get("id", "")),
            name=p.get("Details", {}).get("PolicyName", p.get("name", "")) if isinstance(p.get("Details"), dict) else p.get("name", ""),
            active=p.get("Active", p.get("active", True)),
        )
        for p in items
    ]
    return ActionResult(data=PlatformList(platforms=platforms))


@chat.function("list_security_events", "Read the Security Events audit trail for the connected CyberArk vault -- who accessed or changed what, and when.", action_type="read", chain_callable=True, data_model=SecurityEventList, event="cyberark-connector.list_security_events")
async def list_security_events(ctx, params: ListSecurityEventsParams) -> ActionResult:
    """Read the Security Events audit trail for the connected CyberArk vault -- who accessed or changed what, and when."""
    c = await _resolve_connection(ctx, params.connection_id)
    client = _client_for(c)
    q: dict = {"limit": params.limit}
    if params.search:
        q["search"] = params.search
    data, _ = await client.request("GET", "/ComponentsMonitoringDetails/PVWA", params=q)
    items = (data or {}).get("Events", data if isinstance(data, list) else [])
    events = [
        SecurityEvent(
            timestamp=str(e.get("Time", e.get("timestamp", ""))),
            user=e.get("User", e.get("user", "")),
            action=e.get("Action", e.get("action", "")),
            safe_name=e.get("Safe", e.get("safeName", "")),
            detail=e.get("Details", e.get("detail", "")),
        )
        for e in items
    ]
    return ActionResult(data=SecurityEventList(events=events))
