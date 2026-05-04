"""MCP Server for FreeIPA.

Exposes FreeIPA JSON-RPC API as MCP tools for AI assistants.
Covers user/host groups, HBAC rules, sudo rules, and compound
forge-cluster setup.
"""

from __future__ import annotations

import atexit
import logging
import sys
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from mcp_common.agent_remediation import mcp_remediation_wrapper
from mcp_common.logging import suppress_ssl_warnings

from ipa_mcp.config import Settings
from ipa_mcp.helpers import (
    extract_hostgroup_members,
    hostgroup_diff,
    normalize_result,
    resolve_hbac_access,
)
from ipa_mcp.ipa_client import IPAClient

logger = logging.getLogger(__name__)

mcp = FastMCP("FreeIPA")
ipa: IPAClient | None = None

_READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}
_WRITE = {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True}


def _get_client() -> IPAClient:
    if ipa is None:
        raise RuntimeError("IPA client is not initialized")
    return ipa


def _extract_results(resp: Any) -> Any:
    """Pull the useful data out of an IPA JSON-RPC response."""
    if isinstance(resp, dict):
        if "result" in resp:
            return resp["result"]
        if "summary" in resp:
            return resp
    return resp


def _exists(fn: Any, name: str) -> bool:
    """Check whether an IPA object exists by calling its _show method."""
    try:
        fn(name)
        return True
    except RuntimeError as e:
        if "not found" in str(e).lower() or "4001" in str(e):
            return False
        logger.warning("Unexpected error checking existence of %s: %s", name, e)
        return False


# ── read tools ───────────────────────────────────────────────────


@mcp.tool(annotations=_READ_ONLY)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_list_groups(criteria: str = "") -> Any:
    """List FreeIPA user groups.

    Args:
        criteria: Optional search string to filter groups.
    """
    return _extract_results(_get_client().group_find(criteria))


@mcp.tool(annotations=_READ_ONLY)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_list_hostgroups(criteria: str = "") -> Any:
    """List FreeIPA host groups.

    Args:
        criteria: Optional search string to filter host groups.
    """
    return _extract_results(_get_client().hostgroup_find(criteria))


@mcp.tool(annotations=_READ_ONLY)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_list_hbac_rules(criteria: str = "") -> Any:
    """List FreeIPA HBAC (host-based access control) rules.

    Args:
        criteria: Optional search string to filter rules.
    """
    return _extract_results(_get_client().hbacrule_find(criteria))


@mcp.tool(annotations=_READ_ONLY)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_list_sudo_rules(criteria: str = "") -> Any:
    """List FreeIPA sudo rules.

    Args:
        criteria: Optional search string to filter rules.
    """
    return _extract_results(_get_client().sudorule_find(criteria))


@mcp.tool(annotations=_READ_ONLY)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_list_users(criteria: str = "") -> Any:
    """List FreeIPA users.

    Args:
        criteria: Optional search string to filter users.
    """
    return _extract_results(_get_client().user_find(criteria))


@mcp.tool(annotations=_READ_ONLY)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_list_hosts(criteria: str = "") -> Any:
    """List FreeIPA hosts.

    Args:
        criteria: Optional search string to filter hosts.
    """
    return _extract_results(_get_client().host_find(criteria))


# ── show tools (with normalized members) ─────────────────────────


@mcp.tool(annotations=_READ_ONLY)
def ipa_show_group(name: str) -> Any:
    """Show details of a FreeIPA user group with normalized membership.

    Returns member_users, member_groups, etc. as readable names
    alongside raw DN fields.

    Args:
        name: Group name.
    """
    return normalize_result(_extract_results(_get_client().group_show(name)))


@mcp.tool(annotations=_READ_ONLY)
def ipa_show_hostgroup(name: str) -> Any:
    """Show details of a FreeIPA host group with normalized membership.

    Returns member_hosts, member_hostgroups, etc. as readable names
    alongside raw DN fields.

    Args:
        name: Host group name.
    """
    return normalize_result(_extract_results(_get_client().hostgroup_show(name)))


@mcp.tool(annotations=_READ_ONLY)
def ipa_show_hbacrule(name: str) -> Any:
    """Show details of a FreeIPA HBAC rule with normalized membership.

    Returns member_users, member_groups, member_hosts, member_hostgroups
    as readable names alongside raw DN fields.

    Args:
        name: HBAC rule name.
    """
    return normalize_result(_extract_results(_get_client().hbacrule_show(name)))


@mcp.tool(annotations=_READ_ONLY)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_show_user(name: str) -> Any:
    """Show details of a FreeIPA user with group memberships and access rules.

    Returns memberof_group, memberofindirect_hbacrule, memberofindirect_sudorule
    as readable names alongside raw fields. Use this to audit a user's permissions.

    Args:
        name: Username (e.g. "mballew").
    """
    return normalize_result(_extract_results(_get_client().user_show(name)))


# ── HBAC test explain ────────────────────────────────────────────


@mcp.tool(annotations=_READ_ONLY)
def ipa_hbactest_explain(user: str, targethost: str, service: str = "sshd") -> Any:
    """Test which HBAC rules grant a user access to a host for a service.

    Tries IPA's native ``hbactest`` first (most accurate). If it fails,
    falls back to client-side evaluation by fetching all rules and
    resolving group memberships locally.

    IMPORTANT: Use ``targethost`` (not ``host``) — IPA's API requires this name.

    Args:
        user: Username to test (e.g. "jdoe").
        targethost: Target host FQDN (e.g. "node1.cloud.together.ai").
        service: PAM service to test (default "sshd").
    """
    return resolve_hbac_access(_get_client(), user, targethost, service)


# ── hostgroup parity diff ───────────────────────────────────────


@mcp.tool(annotations=_READ_ONLY)
def ipa_hostgroup_diff(
    hostgroup: str,
    expected_hosts: list[str],
) -> Any:
    """Compare current hostgroup members against an expected list (dry-run).

    Returns lists of hosts to_add, to_remove, and unchanged. Useful for
    comparing IPA hostgroup membership against a source of truth like NetBox.

    Args:
        hostgroup: Name of the IPA host group.
        expected_hosts: List of FQDNs that should be in the group.
    """
    current = extract_hostgroup_members(_get_client(), hostgroup)
    diff = hostgroup_diff(current, expected_hosts)
    return {"hostgroup": hostgroup, **diff}


# ── write tools ──────────────────────────────────────────────────


@mcp.tool(annotations=_WRITE)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_create_group(name: str, description: str = "") -> Any:
    """Create a FreeIPA user group.

    Args:
        name: Group name (e.g. "ug_forge_mycluster").
        description: Optional group description.
    """
    c = _get_client()
    kw: dict[str, Any] = {}
    if description:
        kw["description"] = description
    return _extract_results(c.group_add(name, **kw))


@mcp.tool(annotations=_WRITE)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_add_group_members(
    name: str,
    users: list[str] | None = None,
    groups: list[str] | None = None,
) -> Any:
    """Add users or groups as members of a user group.

    Args:
        name: Target group name.
        users: List of usernames to add.
        groups: List of group names to add as nested members.
    """
    c = _get_client()
    kw: dict[str, Any] = {}
    if users:
        kw["user"] = users
    if groups:
        kw["group"] = groups
    if not kw:
        raise ToolError("Provide at least one of users or groups")
    return _extract_results(c.group_add_member(name, **kw))


@mcp.tool(annotations=_WRITE)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_create_hostgroup(name: str, description: str = "") -> Any:
    """Create a FreeIPA host group.

    Args:
        name: Host group name (e.g. "hg_forge_mycluster").
        description: Optional description.
    """
    c = _get_client()
    kw: dict[str, Any] = {}
    if description:
        kw["description"] = description
    return _extract_results(c.hostgroup_add(name, **kw))


@mcp.tool(annotations=_WRITE)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_add_hostgroup_members(
    name: str,
    hosts: list[str] | None = None,
    hostgroups: list[str] | None = None,
) -> Any:
    """Add hosts or nested host groups to a host group.

    Args:
        name: Target host group name.
        hosts: List of FQDNs to add.
        hostgroups: List of host group names to add as nested members.
    """
    c = _get_client()
    kw: dict[str, Any] = {}
    if hosts:
        kw["host"] = hosts
    if hostgroups:
        kw["hostgroup"] = hostgroups
    if not kw:
        raise ToolError("Provide at least one of hosts or hostgroups")
    return _extract_results(c.hostgroup_add_member(name, **kw))


@mcp.tool(annotations=_WRITE)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_remove_hostgroup_members(
    name: str,
    hosts: list[str] | None = None,
    hostgroups: list[str] | None = None,
) -> Any:
    """Remove hosts or nested host groups from a host group.

    Args:
        name: Target host group name.
        hosts: List of FQDNs to remove.
        hostgroups: List of host group names to remove.
    """
    c = _get_client()
    kw: dict[str, Any] = {}
    if hosts:
        kw["host"] = hosts
    if hostgroups:
        kw["hostgroup"] = hostgroups
    if not kw:
        raise ToolError("Provide at least one of hosts or hostgroups")
    return _extract_results(c.hostgroup_remove_member(name, **kw))


@mcp.tool(annotations=_WRITE)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_create_hbac_rule(
    name: str,
    servicecat: str = "all",
    description: str = "",
) -> Any:
    """Create a FreeIPA HBAC rule.

    Args:
        name: Rule name (e.g. "allow_forge_mycluster").
        servicecat: Service category — "all" grants access to all services.
        description: Optional description.
    """
    c = _get_client()
    kw: dict[str, Any] = {"servicecat": servicecat}
    if description:
        kw["description"] = description
    return _extract_results(c.hbacrule_add(name, **kw))


@mcp.tool(annotations=_WRITE)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_add_hbac_rule_members(
    name: str,
    usergroups: list[str] | None = None,
    hostgroups: list[str] | None = None,
    users: list[str] | None = None,
    hosts: list[str] | None = None,
) -> Any:
    """Add user groups and host groups to an HBAC rule.

    Args:
        name: HBAC rule name.
        usergroups: User groups to grant access.
        hostgroups: Host groups to add as targets.
        users: Individual users to grant access.
        hosts: Individual hosts to add as targets.
    """
    c = _get_client()
    results: list[Any] = []

    user_kw: dict[str, Any] = {}
    if usergroups:
        user_kw["group"] = usergroups
    if users:
        user_kw["user"] = users
    if user_kw:
        results.append(_extract_results(c.hbacrule_add_user(name, **user_kw)))

    host_kw: dict[str, Any] = {}
    if hostgroups:
        host_kw["hostgroup"] = hostgroups
    if hosts:
        host_kw["host"] = hosts
    if host_kw:
        results.append(_extract_results(c.hbacrule_add_host(name, **host_kw)))

    if not results:
        raise ToolError("Provide at least one of usergroups, hostgroups, users, or hosts")
    return results


@mcp.tool(annotations=_WRITE)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_create_sudo_rule(
    name: str,
    cmdcat: str = "all",
    runasusercategory: str = "all",
    runasgroupcategory: str = "all",
    description: str = "",
) -> Any:
    """Create a FreeIPA sudo rule.

    Args:
        name: Sudo rule name (e.g. "allow_sudo_mycluster").
        cmdcat: Command category — "all" allows all commands.
        runasusercategory: RunAs user category — "all" for any user.
        runasgroupcategory: RunAs group category — "all" for any group.
        description: Optional description.
    """
    c = _get_client()
    kw: dict[str, Any] = {
        "cmdcat": cmdcat,
        "ipasudorunasusercategory": runasusercategory,
        "ipasudorunasgroupcategory": runasgroupcategory,
    }
    if description:
        kw["description"] = description
    return _extract_results(c.sudorule_add(name, **kw))


@mcp.tool(annotations=_WRITE)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_add_sudo_rule_members(
    name: str,
    usergroups: list[str] | None = None,
    hostgroups: list[str] | None = None,
    users: list[str] | None = None,
    hosts: list[str] | None = None,
) -> Any:
    """Add user groups and host groups to a sudo rule.

    Args:
        name: Sudo rule name.
        usergroups: User groups to grant sudo.
        hostgroups: Host groups where sudo applies.
        users: Individual users to grant sudo.
        hosts: Individual hosts where sudo applies.
    """
    c = _get_client()
    results: list[Any] = []

    user_kw: dict[str, Any] = {}
    if usergroups:
        user_kw["group"] = usergroups
    if users:
        user_kw["user"] = users
    if user_kw:
        results.append(_extract_results(c.sudorule_add_user(name, **user_kw)))

    host_kw: dict[str, Any] = {}
    if hostgroups:
        host_kw["hostgroup"] = hostgroups
    if hosts:
        host_kw["host"] = hosts
    if host_kw:
        results.append(_extract_results(c.sudorule_add_host(name, **host_kw)))

    if not results:
        raise ToolError("Provide at least one of usergroups, hostgroups, users, or hosts")
    return results


@mcp.tool(annotations=_WRITE)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_add_sudo_option(name: str, option: str) -> Any:
    """Add a sudo option to a sudo rule.

    Args:
        name: Sudo rule name.
        option: Sudo option string (e.g. "!authenticate").
    """
    return _extract_results(_get_client().sudorule_add_option(name, ipasudoopt=option))


# ── compound tool ────────────────────────────────────────────────


@mcp.tool(annotations=_WRITE)
@mcp_remediation_wrapper(project_repo="vhspace/ipa-mcp")
def ipa_setup_forge(
    name: str,
    hosts: list[str],
    users: list[str] | None = None,
) -> dict[str, Any]:
    """One-shot forge cluster IPA setup.

    Creates all user groups, host groups, HBAC rules, and sudo rules
    needed for a forge cluster. Idempotent — skips resources that
    already exist.

    Steps performed:
      1. Create user group ``ug_forge_<name>``
      2. Create host group ``hg_forge_<name>``
      3. Add hosts to host group
      4. Add users to user group
      5. Create HBAC rule ``allow_forge_<name>`` (servicecat=all)
      6. Add user group + host group to HBAC rule
      7. Create sudo rule ``allow_sudo_<name>`` (cmdcat=all, runasuser=all, runasgroup=all)
      8. Add ``!authenticate`` sudo option
      9. Add user group + host group to sudo rule
     10. Add host group to ``allow_forge_together_support`` HBAC rule
     11. Add host group to ``allow_sudo_together_forge-support`` sudo rule

    Args:
        name: Forge cluster identifier (e.g. "cartesia5").
        hosts: List of host FQDNs to add.
        users: Optional list of users to add to the user group.
    """
    c = _get_client()
    ug = f"ug_forge_{name}"
    hg = f"hg_forge_{name}"
    hbac = f"allow_forge_{name}"
    sudo = f"allow_sudo_{name}"
    log: list[str] = []

    # 1. User group
    if _exists(c.group_show, ug):
        log.append(f"User group {ug} already exists")
    else:
        c.group_add(ug, description=f"Forge cluster {name} users")
        log.append(f"Created user group {ug}")

    # 2. Host group
    if _exists(c.hostgroup_show, hg):
        log.append(f"Host group {hg} already exists")
    else:
        c.hostgroup_add(hg, description=f"Forge cluster {name} hosts")
        log.append(f"Created host group {hg}")

    # 3. Add hosts
    if hosts:
        c.hostgroup_add_member(hg, host=hosts)
        log.append(f"Added {len(hosts)} host(s) to {hg}")

    # 4. Add users
    if users:
        c.group_add_member(ug, user=users)
        log.append(f"Added {len(users)} user(s) to {ug}")

    # 5. HBAC rule
    if _exists(c.hbacrule_show, hbac):
        log.append(f"HBAC rule {hbac} already exists")
    else:
        c.hbacrule_add(hbac, servicecat="all", description=f"Forge {name} access")
        log.append(f"Created HBAC rule {hbac}")

    # 6. HBAC members
    c.hbacrule_add_user(hbac, group=[ug])
    c.hbacrule_add_host(hbac, hostgroup=[hg])
    log.append(f"Added {ug} and {hg} to HBAC rule {hbac}")

    # 7. Sudo rule
    if _exists(c.sudorule_show, sudo):
        log.append(f"Sudo rule {sudo} already exists")
    else:
        c.sudorule_add(
            sudo,
            cmdcat="all",
            ipasudorunasusercategory="all",
            ipasudorunasgroupcategory="all",
            description=f"Forge {name} sudo",
        )
        log.append(f"Created sudo rule {sudo}")

    # 8. Sudo option
    try:
        c.sudorule_add_option(sudo, ipasudoopt="!authenticate")
        log.append(f"Added !authenticate to {sudo}")
    except RuntimeError:
        log.append(f"!authenticate already set on {sudo}")

    # 9. Sudo members
    c.sudorule_add_user(sudo, group=[ug])
    c.sudorule_add_host(sudo, hostgroup=[hg])
    log.append(f"Added {ug} and {hg} to sudo rule {sudo}")

    # 10. Together support HBAC
    try:
        c.hbacrule_add_host("allow_forge_together_support", hostgroup=[hg])
        log.append(f"Added {hg} to allow_forge_together_support")
    except RuntimeError as e:
        log.append(f"Could not add {hg} to allow_forge_together_support: {e}")

    # 11. Together support sudo
    try:
        c.sudorule_add_host("allow_sudo_together_forge-support", hostgroup=[hg])
        log.append(f"Added {hg} to allow_sudo_together_forge-support")
    except RuntimeError as e:
        log.append(f"Could not add {hg} to allow_sudo_together_forge-support: {e}")

    return {
        "forge": name,
        "user_group": ug,
        "host_group": hg,
        "hbac_rule": hbac,
        "sudo_rule": sudo,
        "log": log,
    }


# ── server lifecycle ─────────────────────────────────────────────


def _initialize(settings: Settings) -> None:
    global ipa
    if ipa is not None:
        return

    logger.info("Starting FreeIPA MCP Server")

    ipa = IPAClient(
        host=settings.host,
        username=settings.username,
        password=settings.password.get_secret_value(),
        verify_ssl=settings.verify_ssl,
    )
    atexit.register(lambda: ipa and ipa.close())
    logger.debug("IPA client initialized for %s", settings.host)


def main() -> None:
    """CLI entry point: ``ipa-mcp`` command."""
    suppress_ssl_warnings()
    try:
        settings = Settings()  # type: ignore[call-arg]
    except Exception as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    try:
        _initialize(settings)
    except Exception as e:
        logger.error("Failed to initialize: %s", e)
        sys.exit(1)

    try:
        mcp.run(transport="stdio")
    except Exception as e:
        logger.error("Failed to start MCP server: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
