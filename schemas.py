"""Pydantic input contracts and SDL result entities for CyberArk Connector."""
from __future__ import annotations

from imperal_sdk import sdl
from pydantic import BaseModel, Field


class NoParams(BaseModel):
    pass


class ConnectionRefParams(BaseModel):
    connection_id: str = Field("", description="Optional saved CyberArk vault connection ID. Omit to use the first connected vault.")


class ConnectCyberArkParams(BaseModel):
    label: str = Field("", description="Friendly vault label, e.g. 'Acme Production Vault'.")
    base_url: str = Field(..., description="PVWA base URL, e.g. 'https://pvwa.acme.com/PasswordVault'.")
    auth_method: str = Field("cyberark", description="Authentication method: 'cyberark' or 'radius'.")
    username: str = Field(..., description="CyberArk username with API access.")
    password: str = Field(..., description="CyberArk password.")


class DisconnectCyberArkParams(ConnectionRefParams):
    connection_id: str = Field(..., description="Saved CyberArk vault connection ID to remove from Imperal.")


class ListSafesParams(ConnectionRefParams):
    search: str = Field("", description="Optional search string matching Safe name.")
    limit: int = Field(50, description="Max Safes to return (1-1000).")


class SafeIdParams(ConnectionRefParams):
    safe_name: str = Field(..., description="CyberArk Safe name (its unique identifier).")


class CreateSafeParams(ConnectionRefParams):
    safe_name: str = Field(..., description="New Safe's unique name.")
    description: str = Field("", description="Optional description.")
    managing_cpm: str = Field("", description="Optional name of the CPM (Central Policy Manager) that manages password rotation for this Safe.")


class SafeMemberParams(ConnectionRefParams):
    safe_name: str = Field(..., description="CyberArk Safe name.")
    member_name: str = Field(..., description="User or group name to add as a Safe member.")
    permissions: dict = Field(default_factory=dict, description="Optional explicit permission flags, e.g. {'UseAccounts': true, 'RetrieveAccounts': true}.")


class ListAccountsParams(ConnectionRefParams):
    search: str = Field("", description="Optional free-text search (matches account name, username, address).")
    safe_name: str = Field("", description="Optional Safe name filter.")
    limit: int = Field(50, description="Max accounts to return (1-1000).")


class AccountIdParams(ConnectionRefParams):
    account_id: str = Field(..., description="CyberArk account ID.")


class CreateAccountParams(ConnectionRefParams):
    safe_name: str = Field(..., description="Safe this account will be stored in.")
    platform_id: str = Field(..., description="Platform ID (account-type template), e.g. 'WinServerLocal', 'UnixSSH'.")
    address: str = Field(..., description="Target system address (hostname or IP).")
    username: str = Field(..., description="Privileged account username.")
    secret: str = Field("", description="Initial password/secret value (optional -- CyberArk can also onboard without one for later rotation).")
    name: str = Field("", description="Optional friendly account name; CyberArk auto-generates one if omitted.")


class UpdateAccountParams(AccountIdParams):
    name: str = Field("", description="New friendly account name.")
    address: str = Field("", description="New target system address.")


class ChangePasswordParams(AccountIdParams):
    new_password: str = Field("", description="Optional explicit new password. Omit to let CyberArk auto-generate one per the account's platform policy.")


class RetrievePasswordParams(AccountIdParams):
    reason: str = Field("", description="Reason/ticket-id for this retrieval, required by Safes configured for dual control or strict auditing.")


class CreateAccessRequestParams(AccountIdParams):
    reason: str = Field(..., description="Business reason for requesting access -- required by CyberArk for the audit trail.")
    multiple_access: bool = Field(False, description="Whether this request permits multiple retrievals instead of a single one.")
    access_from: str = Field("", description="ISO 8601 start time for the access window (optional).")
    access_to: str = Field("", description="ISO 8601 end time for the access window (optional).")


class AccessRequestIdParams(ConnectionRefParams):
    request_id: str = Field(..., description="CyberArk access request ID.")


class ListAccessRequestsParams(ConnectionRefParams):
    account_id: str = Field(..., description="CyberArk account ID to list access requests for.")
    status_filter: str = Field("", description="Optional status filter: pending, confirmed, cancelled.")


class ListApplicationsParams(ConnectionRefParams):
    pass


class ApplicationIdParams(ConnectionRefParams):
    app_id: str = Field(..., description="CyberArk Application (AAM/CCP) ID.")


class ListPlatformsParams(ConnectionRefParams):
    active_only: bool = Field(True, description="Only return active platforms.")


class ListSecurityEventsParams(ConnectionRefParams):
    search: str = Field("", description="Optional free-text filter (user, safe, or action).")
    limit: int = Field(50, description="Max events to return (1-500).")


class AuditSafesParams(ConnectionRefParams):
    pass


# ---- SDL result entities ----

class CyberArkConnection(sdl.Entity):
    connection_id: str
    label: str
    base_url: str
    auth_method: str


class ConnectionList(sdl.Entity):
    connections: list[CyberArkConnection]


class DeleteResult(sdl.Entity):
    ok: bool
    detail: str = ""


class CyberArkSafe(sdl.Entity):
    safe_name: str
    description: str = ""
    member_count: int = 0
    managing_cpm: str = ""


class SafeList(sdl.Entity):
    safes: list[CyberArkSafe]


class SafeMember(sdl.Entity):
    member_name: str
    member_type: str = ""
    permissions: dict = {}


class SafeMemberList(sdl.Entity):
    members: list[SafeMember]


class CyberArkAccount(sdl.Entity):
    account_id: str
    name: str = ""
    safe_name: str = ""
    platform_id: str = ""
    username: str = ""
    address: str = ""
    last_success_change: str = ""


class AccountList(sdl.Entity):
    accounts: list[CyberArkAccount]


class RetrievedPassword(sdl.Entity):
    account_id: str
    password: str


class AccessRequest(sdl.Entity):
    request_id: str
    account_id: str
    status: str = ""
    reason: str = ""
    requestor: str = ""


class AccessRequestList(sdl.Entity):
    requests: list[AccessRequest]


class CyberArkApplication(sdl.Entity):
    app_id: str
    description: str = ""
    disabled: bool = False


class ApplicationList(sdl.Entity):
    applications: list[CyberArkApplication]


class CyberArkPlatform(sdl.Entity):
    platform_id: str
    name: str = ""
    active: bool = True


class PlatformList(sdl.Entity):
    platforms: list[CyberArkPlatform]


class SecurityEvent(sdl.Entity):
    timestamp: str = ""
    user: str = ""
    action: str = ""
    safe_name: str = ""
    detail: str = ""


class SecurityEventList(sdl.Entity):
    events: list[SecurityEvent]


class HealthAudit(sdl.Entity):
    safe_count: int
    account_count: int
    accounts_overdue_rotation: int
    safes_without_owner: int
    findings: list[str] = []
