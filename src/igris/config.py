from pathlib import Path
import warnings
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IGRIS_", env_file=".env", extra="ignore")
    bind_mode: str = "localhost"
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8787,gt=0,le=65535)

    @field_validator("bind_mode", mode="before")
    @classmethod
    def validate_bind_mode(cls, value: object) -> str:
        mode = str(value).strip().lower()
        if mode in {"localhost", "network"}:
            return mode
        warnings.warn(
            f"Invalid IGRIS_BIND_MODE={value!r}; falling back to 'localhost'.",
            RuntimeWarning,
            stacklevel=2,
        )
        return "localhost"

    @property
    def resolved_bind_host(self) -> str:
        if "bind_host" in self.model_fields_set:
            return self.bind_host
        return "0.0.0.0" if self.bind_mode == "network" else "127.0.0.1"
    allowed_hosts: str = "127.0.0.1,localhost,[::1]"
    password_verifier: str | None = None
    password_verifier_file: str | None = None
    session_ttl_seconds: int = Field(default=8 * 60 * 60, gt=0)
    login_max_failures: int = Field(default=5, gt=0)
    login_failure_window_seconds: int = Field(default=60, gt=0)
    login_max_parallel_checks: int = Field(default=2, gt=0, le=8)
    database_path: str = str(Path.home() / ".local" / "share" / "igris" / "igris.db")
    retention_hours: int = Field(default=24,gt=0)
    soft_disk_cap_mb: int = Field(default=512,gt=0)
    poll_interval: float = Field(default=1.0,gt=0)
    exec_poll_interval: float = Field(default=0.2,gt=0)
    collector_enabled: bool = True
    ptr_fallback: bool = False
    static_dir: str = str(Path(__file__).parent / "static")
    network_tools: str = "curl,wget,ping,ping6,dig,nslookup,host,nc,ncat,ssh"

    @property
    def network_tool_set(self) -> set[str]:
        return {part.strip() for part in self.network_tools.split(",") if part.strip()}

    @property
    def allowed_host_list(self)->list[str]:
        return [part.strip() for part in self.allowed_hosts.split(",") if part.strip()]

    def resolve_password_verifier(self)->str|None:
        if self.password_verifier: return self.password_verifier
        if not self.password_verifier_file: return None
        from .auth import read_password_verifier
        return read_password_verifier(self.password_verifier_file)
