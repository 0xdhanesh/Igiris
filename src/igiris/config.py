from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IGIRIS_", env_file=".env", extra="ignore")
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8787,gt=0,le=65535)
    allowed_hosts: str = "127.0.0.1,localhost,[::1]"
    api_token: str | None = None
    api_token_file: str | None = None
    database_path: str = str(Path.home() / ".local" / "share" / "igiris" / "igiris.db")
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

    def resolve_api_token(self)->str|None:
        if self.api_token: return self.api_token
        if not self.api_token_file: return None
        token=Path(self.api_token_file).read_text().strip()
        if not token: raise ValueError("Configured API token file is empty")
        return token
