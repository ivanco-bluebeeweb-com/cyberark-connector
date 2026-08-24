"""Thin CyberArk PVWA REST API client.

Auth model: CyberArk-native or RADIUS logon returns a raw session token string
(no "Bearer" prefix) used as the value of the Authorization header on every
subsequent call. Token idle-expires (commonly ~20 min); this client
transparently re-authenticates on a 401.
"""
from __future__ import annotations

from typing import Any

import httpx


class CyberArkError(RuntimeError):
    """A safe provider-facing error; never includes credentials."""

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


class CyberArkClient:
    """REST client for the CyberArk PVWA API, scoped to one vault."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        auth_method: str = "cyberark",
        *,
        timeout: float = 30.0,
    ):
        url = (base_url or "").strip().rstrip("/")
        if not url:
            raise CyberArkError("PVWA base URL is required.")
        if not username or not password:
            raise CyberArkError("Username and password are required.")
        method = (auth_method or "cyberark").strip().lower()
        if method not in ("cyberark", "radius"):
            raise CyberArkError(f"Unknown auth method '{auth_method}'. Use 'cyberark' or 'radius'.")
        if not url.endswith("/API") and "/API" not in url:
            url = url + "/API"
        self.base_url = url
        self.username = username
        self.password = password
        self.auth_method = method
        self.timeout = timeout
        self._token: str | None = None

    async def _logon(self) -> str:
        endpoint = "Cyberark" if self.auth_method == "cyberark" else "RADIUS"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/auth/{endpoint}/Logon",
                json={
                    "username": self.username,
                    "password": self.password,
                    "concurrentSession": True,
                },
            )
        if resp.status_code >= 400:
            raise CyberArkError(self._friendly_error(resp))
        token = resp.text.strip().strip('"')
        if not token:
            raise CyberArkError("CyberArk returned an empty session token.")
        self._token = token
        return token

    def _friendly_error(self, resp: httpx.Response) -> str:
        try:
            data = resp.json()
            code = data.get("ErrorCode", "")
            msg = data.get("ErrorMessage", resp.text)
        except Exception:  # noqa: BLE001
            code, msg = "", resp.text
        if code == "ITATS982E" or resp.status_code == 401:
            return "Invalid CyberArk credentials or expired session. Reconnect with a valid username/password."
        if code and "PASWS004" in code:
            return f"{msg} — this Safe requires prior confirmation; use create_access_request first."
        return f"CyberArk API error {resp.status_code}: {msg}" + (f" ({code})" if code else "")

    async def request(
        self, method: str, path: str, *, params: dict | None = None, json_body: Any = None,
    ) -> tuple[Any, httpx.Response]:
        if not self._token:
            await self._logon()
        url = f"{self.base_url}{path}"
        headers = {"Authorization": self._token or ""}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.request(method, url, params=params, json=json_body, headers=headers)
            if resp.status_code == 401:
                await self._logon()
                headers["Authorization"] = self._token or ""
                resp = await client.request(method, url, params=params, json=json_body, headers=headers)
        if resp.status_code >= 400:
            raise CyberArkError(self._friendly_error(resp), retryable=resp.status_code >= 500)
        if not resp.text:
            return None, resp
        try:
            return resp.json(), resp
        except Exception:  # noqa: BLE001
            return resp.text, resp
