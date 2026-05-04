> **Mirror notice.** This repository is a personal mirror of `vhspace/ipa-mcp` v1.3.0, restored from a locally-cached wheel after the upstream repository was removed from GitHub. The source is preserved as-is under its original Apache-2.0 license.
>
> **Caveat:** the package depends on `mcp-common` (also from the archived `vhspace` org, distinct from the unrelated PyPI package of the same name). Until that dependency is mirrored or replaced, the source here is preserved but not yet end-to-end installable from a clean checkout.

# IPA MCP Server

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

MCP server and CLI for [FreeIPA](https://www.freeipa.org/) — manages user groups, host groups, HBAC rules, and sudo rules via the FreeIPA JSON-RPC API. Designed for forge cluster bringup and access control automation in the Together AI SRE stack.

## Quick Start

### Cursor IDE

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "ipa-mcp": {
      "command": "uvx",
      "args": ["--from", "ipa-mcp", "ipa-mcp"],
      "env": {
        "IPA_HOST": "ipa.example.com",
        "IPA_USERNAME": "admin",
        "IPA_PASSWORD": "your-password"
      }
    }
  }
}
```

### From Source

```bash
cd ipa-mcp
uv sync --all-groups
uv run ipa-mcp
```

## Tools

### Read Tools (6)

| Tool | Description |
|------|-------------|
| `ipa_list_groups` | List user groups |
| `ipa_list_hostgroups` | List host groups |
| `ipa_list_hbac_rules` | List HBAC rules |
| `ipa_list_sudo_rules` | List sudo rules |
| `ipa_list_users` | List users |
| `ipa_list_hosts` | List hosts |

### Write Tools (10)

| Tool | Description |
|------|-------------|
| `ipa_create_group` | Create user group |
| `ipa_add_group_members` | Add users to group |
| `ipa_create_hostgroup` | Create host group |
| `ipa_add_hostgroup_members` | Add hosts to host group |
| `ipa_create_hbac_rule` | Create HBAC rule |
| `ipa_add_hbac_rule_members` | Add members to HBAC rule |
| `ipa_create_sudo_rule` | Create sudo rule |
| `ipa_add_sudo_rule_members` | Add members to sudo rule |
| `ipa_add_sudo_option` | Add sudo option |
| `ipa_setup_forge` | One-shot forge cluster setup (groups + HBAC + sudo) |

## CLI

The companion `ipa-cli` provides the same capabilities via shell commands.

| Task | Command |
|------|---------|
| List user groups | `ipa-cli groups` |
| List host groups | `ipa-cli hostgroups` |
| List HBAC rules | `ipa-cli hbac-rules` |
| List sudo rules | `ipa-cli sudo-rules` |
| List users | `ipa-cli users` |
| List hosts | `ipa-cli hosts` |
| Create user group | `ipa-cli create-group <name> --desc "description"` |
| Create host group | `ipa-cli create-hostgroup <name>` |
| Full forge setup | `ipa-cli setup-forge <cluster> --hosts "host1,host2" --users "alice,bob"` |

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IPA_HOST` | Yes | — | FreeIPA server hostname or URL |
| `IPA_USERNAME` | No | `admin` | IPA API username |
| `IPA_PASSWORD` | Yes | — | IPA admin password |
| `IPA_VERIFY_SSL` | No | `false` | SSL certificate verification |

Aliases: `IPA_URL` for `IPA_HOST`, `IPA_USER` for `IPA_USERNAME`, `IPA_PASS` for `IPA_PASSWORD`.

## License

Apache License 2.0
