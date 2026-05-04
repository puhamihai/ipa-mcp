"""HTTP client for FreeIPA JSON-RPC API.

Auth flow: POST form-encoded credentials to /ipa/session/login_password,
then use the session cookie for subsequent JSON-RPC calls to /ipa/json.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_IPA_API_VERSION = "2.252"


@dataclass(slots=True)
class IPAClient:
    """FreeIPA JSON-RPC client with session-cookie authentication."""

    host: str
    username: str
    password: str
    verify_ssl: bool = False

    _client: httpx.Client = field(init=False, repr=False)
    _session_cookie: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.host = self.host.rstrip("/")
        if not self.host.startswith("http"):
            self.host = f"https://{self.host}"
        self._client = httpx.Client(
            verify=self.verify_ssl,
            timeout=httpx.Timeout(30.0),
            headers={"Referer": f"{self.host}/ipa"},
        )
        self._login()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> IPAClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _login(self) -> None:
        """Authenticate and store the session cookie."""
        url = f"{self.host}/ipa/session/login_password"
        r = self._client.post(
            url,
            data={"user": self.username, "password": self.password},
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/plain",
                "Referer": f"{self.host}/ipa",
            },
        )
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"IPA login failed: {e.response.status_code} {e.response.text}"
            ) from e

        cookie = r.cookies.get("ipa_session")
        if not cookie:
            raise RuntimeError("No ipa_session cookie in login response")
        self._session_cookie = cookie
        self._client.cookies.set("ipa_session", cookie)
        logger.debug("Authenticated with FreeIPA at %s", self.host)

    def _call(
        self,
        method: str,
        args: list[Any] | None = None,
        kw: dict[str, Any] | None = None,
        *,
        _retried: bool = False,
    ) -> Any:
        """Execute a JSON-RPC call against /ipa/json."""
        if self._session_cookie is None:
            self._login()
        assert self._session_cookie is not None

        payload = {
            "method": method,
            "params": [
                args or [],
                {**(kw or {}), "version": _IPA_API_VERSION},
            ],
            "id": 0,
        }
        r = self._client.post(
            f"{self.host}/ipa/json",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Referer": f"{self.host}/ipa",
            },
        )
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401 and not _retried:
                self._login()
                return self._call(method, args, kw, _retried=True)
            raise RuntimeError(
                f"IPA {method} failed: {e.response.status_code} {e.response.text}"
            ) from e

        body = r.json()
        if body.get("error"):
            err = body["error"]
            raise RuntimeError(f"IPA {method} error {err.get('code')}: {err.get('message')}")
        return body.get("result", body)

    # ── user groups ──────────────────────────────────────────────

    def group_find(self, criteria: str = "", **kw: Any) -> Any:
        return self._call("group_find", [criteria], kw)

    def group_add(self, name: str, **kw: Any) -> Any:
        return self._call("group_add", [name], kw)

    def group_add_member(self, name: str, **kw: Any) -> Any:
        return self._call("group_add_member", [name], kw)

    def group_show(self, name: str, **kw: Any) -> Any:
        return self._call("group_show", [name], kw)

    # ── host groups ──────────────────────────────────────────────

    def hostgroup_find(self, criteria: str = "", **kw: Any) -> Any:
        return self._call("hostgroup_find", [criteria], kw)

    def hostgroup_add(self, name: str, **kw: Any) -> Any:
        return self._call("hostgroup_add", [name], kw)

    def hostgroup_add_member(self, name: str, **kw: Any) -> Any:
        return self._call("hostgroup_add_member", [name], kw)

    def hostgroup_show(self, name: str, **kw: Any) -> Any:
        return self._call("hostgroup_show", [name], kw)

    # ── HBAC rules ───────────────────────────────────────────────

    def hbacrule_find(self, criteria: str = "", **kw: Any) -> Any:
        return self._call("hbacrule_find", [criteria], kw)

    def hbacrule_add(self, name: str, **kw: Any) -> Any:
        return self._call("hbacrule_add", [name], kw)

    def hbacrule_add_host(self, name: str, **kw: Any) -> Any:
        return self._call("hbacrule_add_host", [name], kw)

    def hbacrule_add_user(self, name: str, **kw: Any) -> Any:
        return self._call("hbacrule_add_user", [name], kw)

    def hbacrule_show(self, name: str, **kw: Any) -> Any:
        return self._call("hbacrule_show", [name], kw)

    # ── sudo rules ───────────────────────────────────────────────

    def sudorule_find(self, criteria: str = "", **kw: Any) -> Any:
        return self._call("sudorule_find", [criteria], kw)

    def sudorule_add(self, name: str, **kw: Any) -> Any:
        return self._call("sudorule_add", [name], kw)

    def sudorule_add_host(self, name: str, **kw: Any) -> Any:
        return self._call("sudorule_add_host", [name], kw)

    def sudorule_add_user(self, name: str, **kw: Any) -> Any:
        return self._call("sudorule_add_user", [name], kw)

    def sudorule_add_option(self, name: str, **kw: Any) -> Any:
        return self._call("sudorule_add_option", [name], kw)

    def sudorule_show(self, name: str, **kw: Any) -> Any:
        return self._call("sudorule_show", [name], kw)

    # ── users ────────────────────────────────────────────────────

    def user_find(self, criteria: str = "", **kw: Any) -> Any:
        return self._call("user_find", [criteria], kw)

    def user_show(self, name: str, **kw: Any) -> Any:
        return self._call("user_show", [name], {**kw, "all": True})

    # ── hosts ────────────────────────────────────────────────────

    def host_find(self, criteria: str = "", **kw: Any) -> Any:
        return self._call("host_find", [criteria], kw)

    # ── HBAC test ─────────────────────────────────────────────

    def hbactest(self, **kw: Any) -> Any:
        return self._call("hbactest", [], kw)

    # ── hostgroup membership mutations ────────────────────────

    def hostgroup_remove_member(self, name: str, **kw: Any) -> Any:
        return self._call("hostgroup_remove_member", [name], kw)
