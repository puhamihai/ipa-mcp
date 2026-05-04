"""Shared helpers for DN normalization, HBAC test explanation, and hostgroup diffing.

Covers Issue #1 (normalized members, hostgroup parity) and
Issue #3 (native hbactest primary, client-side fallback).
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── DN normalization ──────────────────────────────────────────────

_DN_RDN_RE = re.compile(r"^(?:cn|uid|fqdn|krbprincipalname)=([^,]+)", re.IGNORECASE)


def dn_to_name(dn: str) -> str:
    """Extract the first RDN value from an LDAP distinguished name.

    ``"cn=admins,cn=groups,cn=accounts,dc=cloud,dc=together,dc=ai"`` → ``"admins"``
    """
    m = _DN_RDN_RE.match(dn)
    return m.group(1) if m else dn


def _normalize_dn_list(raw: list[str] | str | None) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    return [dn_to_name(d) for d in raw]


_MEMBER_DN_FIELDS = {
    "member_user": "member_users",
    "member_group": "member_groups",
    "memberof_group": "memberof_groups",
    "member_host": "member_hosts",
    "member_hostgroup": "member_hostgroups",
    "memberhost_host": "member_hosts",
    "memberhost_hostgroup": "member_hostgroups",
    "memberuser_user": "member_users",
    "memberuser_group": "member_groups",
    "memberof_hostgroup": "memberof_hostgroups",
    "memberof_hbacrule": "memberof_hbacrules",
    "memberof_sudorule": "memberof_sudorules",
}


def normalize_members(record: dict[str, Any]) -> dict[str, Any]:
    """Add ``member_users``, ``member_groups``, etc. alongside raw DN arrays.

    Raw DN fields are preserved under ``raw_<original_key>``.
    """
    out = dict(record)
    for raw_key, norm_key in _MEMBER_DN_FIELDS.items():
        raw_val = record.get(raw_key)
        if raw_val is not None:
            out[f"raw_{raw_key}"] = raw_val
            existing = out.get(norm_key, [])
            out[norm_key] = existing + _normalize_dn_list(raw_val)
    return out


def normalize_result(resp: Any) -> Any:
    """Normalize a single result dict or a list of result dicts."""
    if isinstance(resp, dict):
        return normalize_members(resp)
    if isinstance(resp, list):
        return [normalize_members(r) if isinstance(r, dict) else r for r in resp]
    return resp


# ── HBAC test — native IPA primary, client-side fallback ─────────


def _flatten(val: Any) -> list[str]:
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        return [val]
    return []


def _extract_result(resp: Any) -> Any:
    """Pull ``result`` from an IPA API response dict."""
    if isinstance(resp, dict) and "result" in resp:
        return resp["result"]
    return resp


def _resolve_user_groups(client: Any, user: str) -> list[str]:
    """Resolve the groups a user belongs to."""
    try:
        user_data = _extract_result(client._call("user_show", [user], {"all": True}))
        if isinstance(user_data, dict):
            raw = user_data.get("memberof_group", [])
            return [dn_to_name(g) if "=" in g else g for g in raw]
    except RuntimeError:
        pass
    return []


def _resolve_host_groups(client: Any, host: str) -> list[str]:
    """Resolve the hostgroups a host belongs to."""
    try:
        host_data = _extract_result(client._call("host_show", [host], {"all": True}))
        if isinstance(host_data, dict):
            raw = host_data.get("memberof_hostgroup", [])
            return [dn_to_name(hg) if "=" in hg else hg for hg in raw]
    except RuntimeError:
        pass
    return []


def _try_native_hbactest(
    client: Any,
    user: str,
    targethost: str,
    service: str,
) -> dict[str, Any] | None:
    """Attempt IPA's native hbactest. Returns result dict or None on failure.

    IPA's hbactest API uses ``targethost`` (not ``host``).
    """
    try:
        resp = client.hbactest(user=user, targethost=targethost, service=service)
        result = _extract_result(resp)
        if isinstance(result, dict) and "value" in result:
            matched = result.get("matched", [])
            notmatched = result.get("notmatched", [])
            return {
                "access_granted": bool(result["value"]),
                "matched_rules": matched if isinstance(matched, list) else [],
                "notmatched_rules": notmatched if isinstance(notmatched, list) else [],
                "method": "native_hbactest",
            }
    except RuntimeError as exc:
        logger.debug("Native hbactest failed, falling back to client-side: %s", exc)
    return None


# ── Client-side HBAC evaluation (fallback) ────────────────────────


def _rule_matches_user(rule: dict[str, Any], user: str, user_groups: list[str]) -> tuple[bool, str]:
    cat = rule.get("usercategory")
    if cat in (["all"], "all"):
        return True, "usercategory=all"

    direct_users = _flatten(rule.get("memberuser_user", []))
    if user in direct_users:
        return True, f"user '{user}' listed directly"

    rule_groups = _flatten(rule.get("memberuser_group", []))
    overlap = set(user_groups) & {dn_to_name(g) for g in rule_groups}
    if overlap:
        return True, f"user is member of group(s): {', '.join(sorted(overlap))}"

    return False, "no user match"


def _rule_matches_host(rule: dict[str, Any], host: str, host_groups: list[str]) -> tuple[bool, str]:
    cat = rule.get("hostcategory")
    if cat in (["all"], "all"):
        return True, "hostcategory=all"

    direct_hosts = _flatten(rule.get("memberhost_host", []))
    direct_fqdns = [dn_to_name(h) for h in direct_hosts]
    if host in direct_fqdns:
        return True, f"host '{host}' listed directly"

    rule_hgs = _flatten(rule.get("memberhost_hostgroup", []))
    overlap = set(host_groups) & {dn_to_name(hg) for hg in rule_hgs}
    if overlap:
        return True, f"host is member of hostgroup(s): {', '.join(sorted(overlap))}"

    return False, "no host match"


def _rule_matches_service(rule: dict[str, Any], service: str) -> tuple[bool, str]:
    cat = rule.get("servicecategory")
    if cat in (["all"], "all"):
        return True, "servicecategory=all"

    direct_svc = _flatten(rule.get("memberservice_hbacsvc", []))
    if service in [dn_to_name(s) for s in direct_svc]:
        return True, f"service '{service}' listed directly"

    svc_groups = _flatten(rule.get("memberservice_hbacsvcgroup", []))
    if svc_groups:
        return True, f"service group(s): {', '.join(dn_to_name(g) for g in svc_groups)}"

    return False, "no service match"


def hbac_evaluate(
    rules: list[dict[str, Any]],
    user: str,
    targethost: str,
    service: str,
    user_groups: list[str] | None = None,
    host_groups: list[str] | None = None,
) -> dict[str, Any]:
    """Client-side HBAC rule evaluation against a user+host+service triple."""
    user_groups = user_groups or []
    host_groups = host_groups or []
    matched: list[dict[str, Any]] = []
    access_granted = False

    for rule in rules:
        enabled = rule.get("ipaenabledflag", [True])
        if enabled in ([False], False, ["FALSE"]):
            continue

        u_match, u_reason = _rule_matches_user(rule, user, user_groups)
        h_match, h_reason = _rule_matches_host(rule, targethost, host_groups)
        s_match, s_reason = _rule_matches_service(rule, service)

        if u_match and h_match and s_match:
            cn = _flatten(rule.get("cn", []))
            rule_name = cn[0] if cn else "unknown"
            access_granted = True
            matched.append(
                {
                    "rule": rule_name,
                    "user_reason": u_reason,
                    "host_reason": h_reason,
                    "service_reason": s_reason,
                }
            )

    return {
        "access_granted": access_granted,
        "matched_rules": [m["rule"] for m in matched],
        "details": matched,
        "method": "client_side",
        "user": user,
        "targethost": targethost,
        "service": service,
    }


def resolve_hbac_access(
    client: Any,
    user: str,
    targethost: str,
    service: str = "sshd",
) -> dict[str, Any]:
    """Test HBAC access: tries IPA native ``hbactest`` first, falls back to client-side.

    The native path uses IPA's server-side rule engine (most accurate).
    If it fails or returns an unexpected shape, we fall back to fetching
    all rules and evaluating locally with resolved group memberships.
    """
    native = _try_native_hbactest(client, user, targethost, service)
    if native is not None:
        native["user"] = user
        native["targethost"] = targethost
        native["service"] = service
        return native

    rules_resp = client.hbacrule_find("", sizelimit=0, all=True)
    rules = _extract_result(rules_resp)
    if isinstance(rules, dict) and "result" in rules:
        rules = rules["result"]
    if not isinstance(rules, list):
        rules = []

    user_groups = _resolve_user_groups(client, user)
    host_groups = _resolve_host_groups(client, targethost)

    return hbac_evaluate(
        rules=rules,
        user=user,
        targethost=targethost,
        service=service,
        user_groups=user_groups,
        host_groups=host_groups,
    )


# ── Hostgroup member extraction ──────────────────────────────────


def extract_hostgroup_members(client: Any, hostgroup: str) -> list[str]:
    """Return current hostgroup members as normalized FQDNs."""
    data = _extract_result(client.hostgroup_show(hostgroup))
    if isinstance(data, dict):
        raw = data.get("member_host", data.get("memberhost_host", []))
    else:
        raw = []
    return [dn_to_name(h) if "=" in str(h) else str(h) for h in raw]


# ── Hostgroup diff ────────────────────────────────────────────────


def hostgroup_diff(
    current_members: list[str],
    expected_members: list[str],
) -> dict[str, list[str]]:
    """Compute the diff between current and expected hostgroup membership."""
    current_set = set(current_members)
    expected_set = set(expected_members)
    return {
        "to_add": sorted(expected_set - current_set),
        "to_remove": sorted(current_set - expected_set),
        "unchanged": sorted(current_set & expected_set),
    }
