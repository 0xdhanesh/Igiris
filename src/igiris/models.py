from __future__ import annotations
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field

EventType = Literal["connect", "dns", "icmp", "exec_network_tool", "live_socket"]
Family = Literal["ipv4", "ipv6", "unknown"]
DomainSource = Literal["observed_dns", "observed_tool_arg", "ptr", "none"]
ArtifactKind = Literal["library", "file"]

class ProcessNode(BaseModel):
    pid: int
    ppid: int
    root_pid: int
    name: str
    exe_path: str | None = None
    exe_hash: str | None = None
    user: str | None = None
    cmdline: str | None = None
    first_seen: datetime
    last_seen: datetime

class Event(BaseModel):
    id: int | None = None
    ts: datetime
    type: EventType
    pid: int
    root_pid: int
    exe_path: str | None = None
    exe_hash: str | None = None
    family: Family = "unknown"
    protocol: str | None = None
    raddr: str | None = None
    rport: int | None = None
    domain: str | None = None
    domain_source: DomainSource = "none"
    success: bool | None = None
    raw_meta: dict[str, Any] = Field(default_factory=dict)

class ProcessArtifact(BaseModel):
    id: int | None = None
    pid: int
    root_pid: int
    kind: ArtifactKind
    path: str
    source: str
    first_seen: datetime
    last_seen: datetime

class ParentSummary(BaseModel):
    root_pid: int
    name: str
    pid: int
    user: str | None
    exe_path: str | None
    exe_hash: str | None
    live_connection_count: int
    history_event_count: int
    latest_persistent_event_id: int = 0
    unique_destination_count: int
    last_activity: datetime
    top_destinations: list[str]
    odd_path: bool = False

class CollectorStatus(BaseModel):
    mode: str
    visibility: str
    privileged: bool
    ebpf_available: bool
    messages: list[str] = Field(default_factory=list)
