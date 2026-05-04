"""Configuration for FreeIPA MCP Server."""

from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


def _find_env_files() -> list[Path]:
    """Build .env search paths: CWD, parent, walk up ancestors, workspace root."""
    paths: list[Path] = [Path(".env"), Path("../.env")]
    for parent in Path.cwd().parents:
        candidate = parent / ".env"
        if candidate.is_file():
            paths.append(candidate)
            break
    workspace = Path("/workspaces/together/.env")
    if workspace.is_file() and workspace not in paths:
        paths.append(workspace)
    return paths


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_find_env_files(),
        env_file_encoding="utf-8",
        env_prefix="IPA_",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    host: str = Field(validation_alias=AliasChoices("IPA_HOST", "IPA_URL"))
    username: str = Field(
        default="admin",
        validation_alias=AliasChoices("IPA_USERNAME", "IPA_USER"),
    )
    password: SecretStr = Field(validation_alias=AliasChoices("IPA_PASSWORD", "IPA_PASS"))
    verify_ssl: bool = Field(default=False)
