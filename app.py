"""CyberArk Connector extension declaration.

CyberArk Privileged Access Manager (PAM) secures, rotates, and audits access
to privileged credentials stored in Safes inside a hardened Digital Vault,
exposed through the PVWA REST API (https://{pvwa-host}/PasswordVault/API/*).
"""
from __future__ import annotations

from imperal_sdk import ChatExtension, Extension

ext = Extension(
    "cyberark-connector",
    version="0.1.0",
    display_name="CyberArk",
    description=(
        "Connect your own CyberArk Privileged Access Manager (PVWA) to manage "
        "Safes, privileged Accounts, credential retrieval/rotation, Just-In-Time "
        "access requests, and Applications, plus review Security Events."
    ),
    icon="icon.svg",
    capabilities=["cyberark:read", "cyberark:write"],
    actions_explicit=True,
    system=False,
)

chat = ChatExtension(
    ext,
    tool_name="cyberark",
    description=(
        "CyberArk Connector — manage Safes, privileged Accounts, credential "
        "retrieval/rotation, Just-In-Time access requests, Applications, "
        "Platforms and Security Events for a PVWA vault."
    ),
)

ext.secret(
    "cyberark_connections",
    "JSON list of connected CyberArk PVWA vaults and encrypted credentials. Managed only through connect_cyberark and disconnect_cyberark.",
    required=True,
    write_mode="both",
    max_bytes=65536,
    rotation_hint_days=90,
)(lambda: None)


@ext.health_check
async def health_check(ctx) -> dict:
    """Report whether at least one CyberArk vault connection is saved."""
    import json

    raw = await ctx.secrets.get("cyberark_connections")
    connections = []
    if raw:
        try:
            connections = json.loads(raw)
        except (TypeError, ValueError):
            connections = []
    return {
        "healthy": True,
        "connected": len(connections) > 0,
        "connection_count": len(connections),
    }
