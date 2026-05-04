"""ipa-cli: CLI wrapper around the FreeIPA JSON-RPC API.

Provides the same capabilities as ipa-mcp but via shell commands,
enabling AI agents to use FreeIPA with fewer tokens than MCP.
"""

from __future__ import annotations

import json
from typing import Any

import typer
from mcp_common.agent_remediation import install_cli_exception_handler

from ipa_mcp.helpers import (
    extract_hostgroup_members,
    hostgroup_diff,
    normalize_result,
    resolve_hbac_access,
)
from ipa_mcp.ipa_client import IPAClient


def _parse_host_list(hosts: str) -> list[str]:
    return [h.strip() for h in hosts.split(",") if h.strip()]


app = typer.Typer(
    name="ipa-cli",
    help="Manage FreeIPA user/host groups, HBAC rules, and sudo rules.",
    no_args_is_help=True,
)
install_cli_exception_handler(app, project_repo="vhspace/ipa-mcp")


def _client() -> IPAClient:
    from ipa_mcp.config import Settings

    try:
        settings = Settings()  # type: ignore[call-arg]
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1) from e
    return IPAClient(
        host=settings.host,
        username=settings.username,
        password=settings.password.get_secret_value(),
        verify_ssl=settings.verify_ssl,
    )


def _output(data: Any, as_json: bool = False) -> None:
    if as_json:
        typer.echo(json.dumps(data, indent=2, default=str))
        return
    if isinstance(data, dict) and "result" in data:
        data = data["result"]
    if isinstance(data, list):
        typer.echo(f"# {len(data)} result(s)")
        for item in data:
            if isinstance(item, dict):
                name = item.get("cn", item.get("uid", item.get("fqdn", ["?"])))
                if isinstance(name, list):
                    name = name[0] if name else "?"
                typer.echo(f"  {name}")
            else:
                typer.echo(f"  {item}")
    elif isinstance(data, dict):
        typer.echo(json.dumps(data, indent=2, default=str))
    else:
        typer.echo(data)


def _extract(resp: Any) -> Any:
    if isinstance(resp, dict) and "result" in resp:
        return resp["result"]
    return resp


@app.command()
def groups(
    criteria: str = typer.Argument("", help="Search string"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """List user groups."""
    with _client() as c:
        _output(_extract(c.group_find(criteria)), as_json=json_output)


@app.command()
def hostgroups(
    criteria: str = typer.Argument("", help="Search string"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """List host groups."""
    with _client() as c:
        _output(_extract(c.hostgroup_find(criteria)), as_json=json_output)


@app.command(name="hbac-rules")
def hbac_rules(
    criteria: str = typer.Argument("", help="Search string"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """List HBAC rules."""
    with _client() as c:
        _output(_extract(c.hbacrule_find(criteria)), as_json=json_output)


@app.command(name="sudo-rules")
def sudo_rules(
    criteria: str = typer.Argument("", help="Search string"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """List sudo rules."""
    with _client() as c:
        _output(_extract(c.sudorule_find(criteria)), as_json=json_output)


@app.command()
def users(
    criteria: str = typer.Argument("", help="Search string"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """List users."""
    with _client() as c:
        _output(_extract(c.user_find(criteria)), as_json=json_output)


@app.command()
def hosts(
    criteria: str = typer.Argument("", help="Search string"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """List hosts."""
    with _client() as c:
        _output(_extract(c.host_find(criteria)), as_json=json_output)


@app.command(name="create-group")
def create_group(
    name: str = typer.Argument(..., help="Group name"),
    description: str = typer.Option("", "--desc", "-d"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """Create a user group."""
    with _client() as c:
        kw: dict[str, Any] = {}
        if description:
            kw["description"] = description
        _output(_extract(c.group_add(name, **kw)), as_json=json_output)


@app.command(name="create-hostgroup")
def create_hostgroup(
    name: str = typer.Argument(..., help="Host group name"),
    description: str = typer.Option("", "--desc", "-d"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """Create a host group."""
    with _client() as c:
        kw: dict[str, Any] = {}
        if description:
            kw["description"] = description
        _output(_extract(c.hostgroup_add(name, **kw)), as_json=json_output)


@app.command(name="show-group")
def show_group(
    name: str = typer.Argument(..., help="Group name"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """Show a user group with normalized membership."""
    with _client() as c:
        _output(normalize_result(_extract(c.group_show(name))), as_json=json_output)


@app.command(name="show-hostgroup")
def show_hostgroup(
    name: str = typer.Argument(..., help="Host group name"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """Show a host group with normalized membership."""
    with _client() as c:
        _output(normalize_result(_extract(c.hostgroup_show(name))), as_json=json_output)


@app.command(name="show-hbacrule")
def show_hbacrule(
    name: str = typer.Argument(..., help="HBAC rule name"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """Show an HBAC rule with normalized membership."""
    with _client() as c:
        _output(normalize_result(_extract(c.hbacrule_show(name))), as_json=json_output)


@app.command(name="show-user")
def show_user(
    name: str = typer.Argument(..., help="Username"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """Show a user with group memberships, HBAC rules, and sudo rules."""
    with _client() as c:
        _output(normalize_result(_extract(c.user_show(name))), as_json=json_output)


@app.command(name="hbactest-explain")
def hbactest_explain(
    user: str = typer.Option(..., "--user", "-u", help="Username to test"),
    targethost: str = typer.Option(..., "--targethost", "-t", help="Target host FQDN"),
    service: str = typer.Option("sshd", "--service", "-s", help="PAM service"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """Test and explain which HBAC rules grant access for a user+host+service.

    Tries IPA native hbactest first, falls back to client-side evaluation.
    """
    with _client() as c:
        result = resolve_hbac_access(c, user, targethost, service)
        _output(result, as_json=json_output)


@app.command(name="hostgroup-diff")
def hostgroup_diff_cmd(
    hostgroup: str = typer.Argument(..., help="Host group name"),
    expected: str = typer.Option(..., "--expected", "-e", help="Comma-separated expected FQDNs"),
    apply: bool = typer.Option(False, "--apply", help="Apply changes (add/remove members)"),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation prompt (non-interactive)"
    ),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """Compare hostgroup membership against an expected host list.

    Default is dry-run. Use --apply to add/remove members.
    Combine with --yes to skip confirmation.
    """
    expected_list = _parse_host_list(expected)
    with _client() as c:
        current = extract_hostgroup_members(c, hostgroup)
        diff = hostgroup_diff(current, expected_list)
        result: dict[str, Any] = {"hostgroup": hostgroup, "mode": "dry-run", **diff}

        if apply:
            if not yes:
                typer.confirm(
                    f"Apply changes to {hostgroup}? "
                    f"Adding {len(diff['to_add'])}, removing {len(diff['to_remove'])}",
                    abort=True,
                )
            if diff["to_add"]:
                c.hostgroup_add_member(hostgroup, host=diff["to_add"])
            if diff["to_remove"]:
                c.hostgroup_remove_member(hostgroup, host=diff["to_remove"])
            result["mode"] = "applied"

        _output(result, as_json=json_output)


@app.command(name="hostgroup-add-hosts")
def hostgroup_add_hosts(
    hostgroup: str = typer.Argument(..., help="Host group name"),
    hosts: str = typer.Argument(..., help="Comma-separated host FQDNs to add"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """Add hosts to a host group."""
    host_list = _parse_host_list(hosts)
    if not host_list:
        typer.echo("Error: hosts must not be empty", err=True)
        raise typer.Exit(1)
    with _client() as c:
        _output(_extract(c.hostgroup_add_member(hostgroup, host=host_list)), as_json=json_output)


@app.command(name="hostgroup-remove-hosts")
def hostgroup_remove_hosts(
    hostgroup: str = typer.Argument(..., help="Host group name"),
    hosts: str = typer.Argument(..., help="Comma-separated host FQDNs to remove"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """Remove hosts from a host group."""
    host_list = _parse_host_list(hosts)
    if not host_list:
        typer.echo("Error: hosts must not be empty", err=True)
        raise typer.Exit(1)
    with _client() as c:
        _output(
            _extract(c.hostgroup_remove_member(hostgroup, host=host_list)),
            as_json=json_output,
        )


@app.command(name="setup-forge")
def setup_forge(
    name: str = typer.Argument(..., help="Forge cluster identifier"),
    hosts_str: str = typer.Option(..., "--hosts", help="Comma-separated host FQDNs"),
    users_str: str = typer.Option("", "--users", help="Comma-separated usernames to add"),
    json_output: bool = typer.Option(False, "--json", "-j"),
) -> None:
    """Run the full forge IPA setup for a cluster.

    Creates user group, host group, HBAC rule, and sudo rule with
    all the standard forge conventions.
    """
    from ipa_mcp.server import ipa_setup_forge

    host_list = _parse_host_list(hosts_str)
    user_list = [u.strip() for u in users_str.split(",") if u.strip()] if users_str else None

    if not host_list:
        typer.echo("Error: --hosts is required and must not be empty", err=True)
        raise typer.Exit(1)

    c = _client()

    import ipa_mcp.server as srv

    srv.ipa = c

    try:
        result = ipa_setup_forge(name=name, hosts=host_list, users=user_list)
        _output(result, as_json=json_output)
    finally:
        srv.ipa = None
        c.close()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
