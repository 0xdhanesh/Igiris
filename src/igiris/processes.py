from __future__ import annotations
import hashlib
import os
from functools import lru_cache
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import psutil
from .models import ProcessNode

SYSTEM_BOUNDARIES = {"systemd", "init", "kthreadd", "gnome-shell", "plasmashell", "sddm", "gdm", "gdm-session-worker", "login", "sshd"}
ODD_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")

@dataclass(frozen=True)
class ProcessSnapshot:
    pid: int
    ppid: int
    name: str
    exe_path: str | None
    cmdline: str | None
    user: str | None

def snapshot_processes() -> dict[int, ProcessSnapshot]:
    table: dict[int, ProcessSnapshot] = {}
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username"]):
        try:
            info = proc.info
            table[info["pid"]] = ProcessSnapshot(
                pid=info["pid"], ppid=info.get("ppid") or 0, name=info.get("name") or f"pid-{info['pid']}",
                exe_path=info.get("exe"), cmdline=" ".join(info.get("cmdline") or []), user=info.get("username"),
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
            continue
    return table

def resolve_root(pid: int, table: dict[int, ProcessSnapshot]) -> int:
    current = table.get(pid)
    if not current:
        return pid
    candidate = current.pid
    seen: set[int] = set()
    while current and current.pid not in seen:
        seen.add(current.pid)
        parent = table.get(current.ppid)
        if not parent or parent.pid <= 1 or parent.name in SYSTEM_BOUNDARIES:
            return candidate
        candidate = parent.pid
        current = parent
    return candidate

@lru_cache(maxsize=1024)
def _sha256_version(path:str,mtime_ns:int,size:int)->str:
    h=hashlib.sha256()
    with open(path,"rb") as handle:
        for chunk in iter(lambda:handle.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def sha256_file(path: str | None) -> str | None:
    if not path:
        return None
    try:
        stat=os.stat(path)
        return _sha256_version(path,stat.st_mtime_ns,stat.st_size)
    except (OSError, PermissionError):
        return None

def is_odd_path(path: str | None) -> bool:
    return bool(path and path.startswith(ODD_PREFIXES))

def _clean_proc_path(value:str)->str:
    return value.removesuffix(" (deleted)")

def _is_library_path(path:str)->bool:
    name=Path(path).name
    return ".so" in name and (name.endswith(".so") or ".so." in name)

def library_paths_from_maps(content:str)->set[str]:
    libraries=set()
    for line in content.splitlines():
        parts=line.split(maxsplit=5)
        if len(parts)<6: continue
        path=_clean_proc_path(parts[5])
        if path.startswith("/") and _is_library_path(path): libraries.add(path)
    return libraries

def file_paths_from_fd_targets(targets)->set[str]:
    files=set()
    for target in targets:
        path=_clean_proc_path(str(target))
        if path.startswith("/") and not _is_library_path(path): files.add(path)
    return files

def snapshot_process_artifacts(pid:int)->tuple[set[str],set[str]]:
    proc=Path("/proc")/str(pid); libraries=set(); targets=[]
    try: libraries=library_paths_from_maps((proc/"maps").read_text(errors="replace"))
    except (OSError,PermissionError): pass
    try:
        for entry in (proc/"fd").iterdir():
            try: targets.append(os.readlink(entry))
            except (OSError,PermissionError): continue
    except (OSError,PermissionError): pass
    return libraries,file_paths_from_fd_targets(targets)

def to_node(snapshot: ProcessSnapshot, root_pid: int, hash_binary: bool = True) -> ProcessNode:
    now = datetime.now(timezone.utc)
    return ProcessNode(pid=snapshot.pid, ppid=snapshot.ppid, root_pid=root_pid, name=snapshot.name,
        exe_path=snapshot.exe_path, exe_hash=sha256_file(snapshot.exe_path) if hash_binary else None,
        user=snapshot.user, cmdline=snapshot.cmdline, first_seen=now, last_seen=now)
