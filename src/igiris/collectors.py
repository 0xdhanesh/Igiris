from __future__ import annotations
import asyncio, ipaddress, os, shlex, socket, time
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path
from threading import Event as ThreadEvent
import psutil
from .config import Settings
from .models import Event, ProcessArtifact
from .processes import ProcessSnapshot, resolve_root, snapshot_process_artifacts, snapshot_processes, to_node
from .store import Store

class DomainCorrelator:
    def __init__(self, ttl_seconds:int=300): self.ttl=ttl_seconds; self._map={}
    def observe(self,pid:int,domain:str,addresses:list[str]):
        expires=time.monotonic()+self.ttl
        for address in addresses: self._map[(pid,address)]=(domain,expires)
    def lookup(self,pid:int,address:str):
        item=self._map.get((pid,address))
        if item and item[1]>=time.monotonic(): return item[0],"observed_dns"
        if item: self._map.pop((pid,address),None)
        return None,"none"

def detect_new_network_tools(previous:set[int],current:dict[int,ProcessSnapshot],tools:set[str])->list[ProcessSnapshot]:
    return sorted((p for pid,p in current.items() if pid not in previous and p.name in tools),key=lambda p:p.pid)

def dns_query_from_tool(snapshot:ProcessSnapshot)->str|None:
    if snapshot.name not in {"dig","nslookup","host"}: return None
    try: parts=shlex.split(snapshot.cmdline or "")[1:]
    except ValueError: parts=(snapshot.cmdline or "").split()[1:]
    record_types={"A","AAAA","ANY","CNAME","MX","NS","PTR","SOA","SRV","TXT"}
    candidates=[part.rstrip(".") for part in parts if not part.startswith(("-","+","@")) and part.upper() not in record_types]
    return candidates[0] if candidates else None

def observed_domain_from_tool(snapshot:ProcessSnapshot)->tuple[str|None,str]:
    """Return a hostname explicitly supplied to a supported network tool."""
    query=dns_query_from_tool(snapshot)
    if query: return query,"observed_dns"
    if snapshot.name not in {"curl","wget"}: return None,"none"
    try: parts=shlex.split(snapshot.cmdline or "")[1:]
    except ValueError: parts=(snapshot.cmdline or "").split()[1:]
    for part in parts:
        if "://" not in part: continue
        hostname=urlparse(part).hostname
        if hostname: return hostname.rstrip(".").lower(),"observed_tool_arg"
    return None,"none"

def persist_lineage(store:Store,pid:int,table:dict[int,ProcessSnapshot],root:int):
    """Persist the active node and every known ancestor through the chosen root."""
    current=table.get(pid); seen=set(); lineage=[]
    while current and current.pid not in seen:
        seen.add(current.pid); lineage.append(current)
        if current.pid==root: break
        current=table.get(current.ppid)
    for snapshot in reversed(lineage):
        store.upsert_process(to_node(snapshot,root))

def persist_advanced_artifacts(store:Store,pid:int,root:int):
    libraries,files=snapshot_process_artifacts(pid); now=datetime.now(timezone.utc)
    artifacts=[ProcessArtifact(pid=pid,root_pid=root,kind="library",path=path,source="proc_maps",first_seen=now,last_seen=now) for path in libraries]
    artifacts.extend(ProcessArtifact(pid=pid,root_pid=root,kind="file",path=path,source="proc_fd",first_seen=now,last_seen=now) for path in files)
    store.upsert_artifacts(artifacts)

def historical_transitions(previous:set[tuple],current:set[tuple])->set[tuple]:
    """Return sockets newly active since the prior snapshot; a close resets history eligibility."""
    return current-previous

def local_interface_addresses()->set[str]:
    addresses={"127.0.0.1","::1"}
    try:
        for entries in psutil.net_if_addrs().values():
            for entry in entries:
                if entry.family in {socket.AF_INET,socket.AF_INET6}: addresses.add(entry.address.split("%",1)[0])
    except (psutil.Error,OSError): pass
    return addresses

def is_internal_api_connection(connection,api_port:int,local_ips:set[str]|None=None)->bool:
    """Ignore both accepted and local client connections to Igiris itself."""
    lport=getattr(connection.laddr,"port",None) if connection.laddr else None
    if lport==api_port: return True
    rport=getattr(connection.raddr,"port",None) if connection.raddr else None
    if rport!=api_port: return False
    remote=getattr(connection.raddr,"ip",None)
    if not remote: return False
    remote=remote.split("%",1)[0]
    try:
        if ipaddress.ip_address(remote).is_loopback: return True
    except ValueError: return False
    return remote in (local_ips or set())

def connection_to_event(conn,table:dict[int,ProcessSnapshot],domains:DomainCorrelator):
    pid=conn.pid; snap=table[pid]; root=resolve_root(pid,table); family="ipv6" if conn.family==socket.AF_INET6 else "ipv4" if conn.family==socket.AF_INET else "unknown"
    protocol="tcp" if conn.type==socket.SOCK_STREAM else "udp" if conn.type==socket.SOCK_DGRAM else "raw"
    raddr=getattr(conn.raddr,"ip",None) if conn.raddr else None; rport=getattr(conn.raddr,"port",None) if conn.raddr else None
    domain,source=domains.lookup(pid,raddr) if raddr else (None,"none")
    if not domain: domain,source=observed_domain_from_tool(snap)
    process=to_node(snap,root)
    event=Event(ts=datetime.now(timezone.utc),type="live_socket",pid=pid,root_pid=root,exe_path=process.exe_path,exe_hash=process.exe_hash,
        family=family,protocol=protocol,raddr=raddr,rport=rport,domain=domain,domain_source=source,
        success=True if getattr(conn,"status","")==psutil.CONN_ESTABLISHED else None,raw_meta={"status":getattr(conn,"status",None),"source":"proc_socket_snapshot"})
    return event,process

def _intent_target(cmdline:str|None)->str|None:
    parts=(cmdline or "").split()
    for part in reversed(parts[1:]):
        if not part.startswith("-"): return part
    return None

class PollingCollector:
    def __init__(self,store:Store,settings:Settings,status:dict):
        self.store=store; self.settings=settings; self.status=status; self.stop_event=ThreadEvent(); self.domains=DomainCorrelator(); self._seen=set(); self._historical=set(); self._local_ips=local_interface_addresses()
    def collect_once(self):
        table=snapshot_processes(); tagged=detect_new_network_tools(self._seen,table,self.settings.network_tool_set)
        for snap in tagged:
            root=resolve_root(snap.pid,table); node=to_node(snap,root); persist_lineage(self.store,snap.pid,table,root); persist_advanced_artifacts(self.store,snap.pid,root); domain,domain_source=observed_domain_from_tool(snap)
            self.store.add_event(Event(ts=datetime.now(timezone.utc),type="exec_network_tool",pid=snap.pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
                family="ipv6" if snap.name=="ping6" else "unknown",protocol=None,domain=domain,domain_source=domain_source,raw_meta={"tool":snap.name,"cmdline":snap.cmdline,"source":"proc_exec_poll"}))
            query=dns_query_from_tool(snap)
            if query:
                self.store.add_event(Event(ts=datetime.now(timezone.utc),type="dns",pid=snap.pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
                    family="unknown",protocol="dns",domain=query,domain_source="observed_dns",raw_meta={"tool":snap.name,"source":"network_tool_exec"}))
            if snap.name in {"ping","ping6"}:
                target=_intent_target(snap.cmdline)
                self.store.add_event(Event(ts=datetime.now(timezone.utc),type="icmp",pid=snap.pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
                    family="ipv6" if snap.name=="ping6" else "ipv4",protocol="icmpv6" if snap.name=="ping6" else "icmp",raddr=target,domain=target if target and not _looks_ip(target) else None,
                    domain_source="none",raw_meta={"best_effort":True,"source":"network_tool_exec"}))
        self._seen=set(table)
        try: connections=psutil.net_connections(kind="inet")
        except (psutil.AccessDenied,OSError): connections=[]
        live_keys=set(); live_events={}
        for conn in connections:
            if is_internal_api_connection(conn,self.settings.bind_port,self._local_ips): continue
            if not conn.pid or conn.pid not in table or not conn.raddr: continue
            try: event,node=connection_to_event(conn,table,self.domains)
            except (KeyError,psutil.Error,OSError): continue
            persist_lineage(self.store,event.pid,table,event.root_pid); persist_advanced_artifacts(self.store,event.pid,event.root_pid); key=(event.pid,event.family,event.protocol,event.raddr,event.rport); live_keys.add(key); live_events[key]=event
        for key in historical_transitions(self._historical,live_keys):
            event=live_events[key]
            hist=event.model_copy(update={"id":None,"type":"dns" if event.rport==53 else "connect","raw_meta":{**event.raw_meta,"source":"proc_socket_observation"}}); self.store.add_event(hist)
        self.store.replace_live_events(list(live_events.values()))
        self._historical=live_keys
        self.store.prune(self.settings.retention_hours)
        self.store.prune_to_cap(self.settings.soft_disk_cap_mb*1024*1024)
    async def run(self):
        self.status.update({"mode":"proc-polling","visibility":"limited","privileged":os.geteuid()==0,"ebpf_available":False,
            "messages":["eBPF unavailable; using /proc socket and process polling.","Short-lived connections, DNS names, and ICMP attribution may be incomplete."]})
        while not self.stop_event.is_set():
            await asyncio.to_thread(self.collect_once); await asyncio.sleep(self.settings.poll_interval)
    def reset_tracking(self):
        self.domains=DomainCorrelator(); self._seen=set(); self._historical=set()
    def stop(self): self.stop_event.set()

def _looks_ip(value:str)->bool:
    try: socket.inet_pton(socket.AF_INET6 if ":" in value else socket.AF_INET,value); return True
    except OSError: return False
