"""CyberArk Connector -- center panels for Safes/Accounts/Access Requests/Applications/Platforms/Security Events."""
from __future__ import annotations

from imperal_sdk import ui

import handlers as h
from app import ext


def _table_or_empty(rows, columns, empty_message, empty_icon):
    if not rows:
        return ui.Empty(message=empty_message, icon=empty_icon)
    return ui.DataTable(rows=rows, columns=columns)


@ext.panel("cyberark_safes", slot="center", title="Safes", center_overlay=True)
async def cyberark_safes(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Lock")
    client = h._client_for(connections[0])
    try:
        data, _ = await client.request("GET", "/Safes", params={"limit": 100})
    except Exception as exc:  # noqa: BLE001
        return ui.Alert(type="error", message=f"Could not load Safes: {exc}")
    items = (data or {}).get("value", [])
    rows = [{
        "safeName": s.get("safeName", ""),
        "description": s.get("description", ""),
        "managingCPM": s.get("managingCPM", ""),
        "memberCount": str(s.get("numberOfVersionsRetention", s.get("memberCount", ""))),
    } for s in items]
    columns = [
        ui.DataColumn(key="safeName", label="Safe"),
        ui.DataColumn(key="description", label="Description"),
        ui.DataColumn(key="managingCPM", label="Managing CPM"),
        ui.DataColumn(key="memberCount", label="Members"),
    ]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Safes", level=2),
        _table_or_empty(rows, columns, "No Safes found", "Lock"),
    ])


@ext.panel("cyberark_accounts", slot="center", title="Accounts", center_overlay=True)
async def cyberark_accounts(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="KeyRound")
    client = h._client_for(connections[0])
    try:
        data, _ = await client.request("GET", "/Accounts", params={"limit": 100})
    except Exception as exc:  # noqa: BLE001
        return ui.Alert(type="error", message=f"Could not load Accounts: {exc}")
    items = (data or {}).get("value", [])
    rows = [{
        "name": a.get("name", ""),
        "safeName": a.get("safeName", ""),
        "platformId": a.get("platformId", ""),
        "userName": a.get("userName", ""),
        "address": a.get("address", ""),
    } for a in items]
    columns = [
        ui.DataColumn(key="name", label="Name"),
        ui.DataColumn(key="safeName", label="Safe"),
        ui.DataColumn(key="platformId", label="Platform"),
        ui.DataColumn(key="userName", label="Username"),
        ui.DataColumn(key="address", label="Address"),
    ]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Accounts", level=2),
        _table_or_empty(rows, columns, "No Accounts found", "KeyRound"),
    ])


@ext.panel("cyberark_applications", slot="center", title="Applications", center_overlay=True)
async def cyberark_applications(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="AppWindow")
    client = h._client_for(connections[0])
    try:
        data, _ = await client.request("GET", "/Applications")
    except Exception as exc:  # noqa: BLE001
        return ui.Alert(type="error", message=f"Could not load Applications: {exc}")
    items = (data or {}).get("application", data if isinstance(data, list) else [])
    rows = [{
        "appId": a.get("AppID", a.get("appId", "")),
        "description": a.get("Description", ""),
        "disabled": "Yes" if a.get("Disabled", False) else "No",
    } for a in items]
    columns = [
        ui.DataColumn(key="appId", label="App ID"),
        ui.DataColumn(key="description", label="Description"),
        ui.DataColumn(key="disabled", label="Disabled"),
    ]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Applications", level=2),
        _table_or_empty(rows, columns, "No Applications found", "AppWindow"),
    ])


@ext.panel("cyberark_platforms", slot="center", title="Platforms", center_overlay=True)
async def cyberark_platforms(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="Layers")
    client = h._client_for(connections[0])
    try:
        data, _ = await client.request("GET", "/Platforms", params={"active": "true"})
    except Exception as exc:  # noqa: BLE001
        return ui.Alert(type="error", message=f"Could not load Platforms: {exc}")
    items = (data or {}).get("Platforms", data if isinstance(data, list) else [])
    rows = []
    for p in items:
        details = p.get("Details", {}) if isinstance(p.get("Details"), dict) else {}
        rows.append({
            "platformId": p.get("PlatformID", p.get("id", "")),
            "name": details.get("PolicyName", p.get("name", "")),
            "active": "Yes" if p.get("Active", p.get("active", True)) else "No",
        })
    columns = [
        ui.DataColumn(key="platformId", label="Platform ID"),
        ui.DataColumn(key="name", label="Name"),
        ui.DataColumn(key="active", label="Active"),
    ]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Platforms", level=2),
        _table_or_empty(rows, columns, "No Platforms found", "Layers"),
    ])


@ext.panel("cyberark_security_events", slot="center", title="Security Events", center_overlay=True)
async def cyberark_security_events(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Empty(message="Nothing to show here", icon="ShieldAlert")
    client = h._client_for(connections[0])
    try:
        data, _ = await client.request("GET", "/RiskySPN/SecurityEvents", params={"limit": 50})
    except Exception as exc:  # noqa: BLE001
        return ui.Alert(type="error", message=f"Could not load Security Events: {exc}")
    items = (data or {}).get("value", data if isinstance(data, list) else [])
    rows = [{
        "timestamp": str(e.get("timestamp", e.get("Timestamp", ""))),
        "user": e.get("user", e.get("User", "")),
        "action": e.get("action", e.get("Action", "")),
        "safeName": e.get("safeName", e.get("Safe", "")),
    } for e in items]
    columns = [
        ui.DataColumn(key="timestamp", label="Time"),
        ui.DataColumn(key="user", label="User"),
        ui.DataColumn(key="action", label="Action"),
        ui.DataColumn(key="safeName", label="Safe"),
    ]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="Security Events", level=2),
        _table_or_empty(rows, columns, "No Security Events found", "ShieldAlert"),
    ])
