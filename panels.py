"""CyberArk Connector panels.

SIDEBAR CONTENT -- NO CARDS ANYWHERE, per ~/UI_INTERFACE_STANDARD.md's
"left sidebar, no decorated cards" rule (same convention as Okta/Ping
Identity Connector's panels.py). Every section is a plain ui.Stack, no Card
border/background/shadow. Disconnect lives only in "App settings"
(panels_settings.py). The one secondary "App settings" button is always the
LAST element at the bottom of the sidebar.

Per Vlad's standing rule: every input carries its own label (not just a
placeholder), placeholders are contextually specific, the form container is
stretched to the full width of the left sidebar with its contents stretched
to fill it, and the sidebar carries NO instructions that duplicate the
"How do I set this up?" modal.
"""
from __future__ import annotations

from imperal_sdk import ui

import handlers as h
from app import ext


def _field(label: str, node: ui.UINode) -> ui.UINode:
    return ui.Stack(direction="v", gap=1, align="stretch", children=[
        ui.Text(label, variant="caption"),
        node,
    ])


def _settings_button() -> ui.UINode:
    return ui.Button(
        "App settings", variant="secondary", size="sm", full_width=True,
        icon="Settings", on_click=ui.Call("__panel__cyberark_settings"),
    )


@ext.panel("cyberark_sidebar", slot="left", title="CyberArk")
async def cyberark_sidebar(ctx, **kwargs) -> ui.UINode:
    connections = await h._load_connections(ctx)
    if not connections:
        return ui.Stack(direction="v", gap=3, align="stretch", children=[
            ui.Button("How do I get this?", variant="ghost", size="sm", icon="HelpCircle",
                      on_click=ui.Call("__panel__cyberark_connect_help")),
            ui.Form(action="connect_cyberark", submit_label="Connect", children=[
                _field("Vault label", ui.Input(param_name="label", placeholder="e.g. Acme Production Vault")),
                _field("Authentication method", ui.Select(param_name="auth_method", value="cyberark", options=[
                    {"label": "CyberArk", "value": "cyberark"},
                    {"label": "RADIUS", "value": "radius"},
                ])),
                _field("PVWA base URL", ui.Input(param_name="base_url", placeholder="https://pvwa.acme.com/PasswordVault")),
                _field("Username", ui.Input(param_name="username", placeholder="API-capable CyberArk username")),
                _field("Password", ui.Password(param_name="password", placeholder="CyberArk password")),
            ], full_width=True),
        ])
    labels = ", ".join(c.get("label") or c.get("base_url", "") for c in connections)
    return ui.Stack(direction="v", gap=1, align="stretch", children=[
        ui.Text(labels, variant="caption"),
        ui.Divider(),
        ui.Button("Safes", variant="ghost", size="sm", full_width=True, icon="Lock",
                  on_click=ui.Call("__panel__cyberark_safes")),
        ui.Button("Accounts", variant="ghost", size="sm", full_width=True, icon="KeyRound",
                  on_click=ui.Call("__panel__cyberark_accounts")),
        ui.Button("Access Requests", variant="ghost", size="sm", full_width=True, icon="ShieldQuestion",
                  on_click=ui.Call("__panel__cyberark_access_requests")),
        ui.Button("Applications", variant="ghost", size="sm", full_width=True, icon="AppWindow",
                  on_click=ui.Call("__panel__cyberark_applications")),
        ui.Button("Platforms", variant="ghost", size="sm", full_width=True, icon="LayoutTemplate",
                  on_click=ui.Call("__panel__cyberark_platforms")),
        ui.Button("Security Events", variant="ghost", size="sm", full_width=True, icon="ScrollText",
                  on_click=ui.Call("__panel__cyberark_events")),
        ui.Divider(),
        _settings_button(),
    ])


@ext.panel("cyberark_connect_help", slot="center", title="Connect CyberArk", center_overlay=True)
async def cyberark_connect_help(ctx, **kwargs) -> ui.UINode:
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Header(text="How to connect CyberArk", level=2),
        ui.Text("1. Ask your CyberArk administrator for an API-capable username/password with access to the Safes you need (PVWA Web Services access must be enabled for that user).", variant="body"),
        ui.Text("2. Find your PVWA base URL -- it looks like https://pvwa.yourcompany.com/PasswordVault.", variant="body"),
        ui.Text("3. Choose CyberArk or RADIUS as the authentication method, matching how that user normally logs in.", variant="body"),
        ui.Text("4. Paste the URL and credentials into the form and press Connect -- we verify them immediately with a real login before saving anything.", variant="body"),
        ui.Alert(type="info", message="Credentials are encrypted at rest and only used to call your own PVWA server on your behalf."),
    ])
