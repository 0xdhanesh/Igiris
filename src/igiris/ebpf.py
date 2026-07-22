from __future__ import annotations
import asyncio, importlib.util, os, platform, socket
from pathlib import Path
from datetime import datetime, timezone
from .collectors import PollingCollector, dns_query_from_tool, persist_advanced_artifacts, persist_lineage
from .models import Event, ProcessArtifact
from .processes import ProcessSnapshot, resolve_root, snapshot_processes, to_node

# BCC program for connect/exec telemetry. DNS and ICMP enrichers remain best-effort and
# use the shared event schema; deployments without BCC fall back to /proc polling.
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <linux/sched.h>
struct evt_t { u32 pid; u32 ppid; u32 kind; s32 retval; u16 family; u16 dport; unsigned char addr[16]; char comm[16]; };
struct file_evt_t { u32 pid; u32 ppid; char path[256]; };
struct pending_t { struct evt_t event; };
BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(file_events);
BPF_HASH(connecting, u64, struct pending_t);
static void identity(struct evt_t *e) {
  e->pid=bpf_get_current_pid_tgid()>>32;
  struct task_struct *task=(struct task_struct *)bpf_get_current_task();
  bpf_probe_read_kernel(&e->ppid,sizeof(e->ppid),&task->real_parent->tgid);
  bpf_get_current_comm(&e->comm,sizeof(e->comm));
}
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
  u64 tid=bpf_get_current_pid_tgid();
  u16 family=0;
  if (!args->uservaddr || args->addrlen < sizeof(family) || bpf_probe_read_user(&family,sizeof(family),(void *)args->uservaddr)) return 0;
  struct pending_t pending={}; identity(&pending.event); pending.event.kind=1; pending.event.family=family;
  if (family==AF_INET) {
    struct sockaddr_in sa={};
    if (args->addrlen < sizeof(sa) || bpf_probe_read_user(&sa,sizeof(sa),(void *)args->uservaddr)) return 0;
    pending.event.dport=sa.sin_port;
    __builtin_memcpy(&pending.event.addr[0],&sa.sin_addr.s_addr,4);
  } else if (family==AF_INET6) {
    struct sockaddr_in6 sa6={};
    if (args->addrlen < sizeof(sa6) || bpf_probe_read_user(&sa6,sizeof(sa6),(void *)args->uservaddr)) return 0;
    pending.event.dport=sa6.sin6_port;
    __builtin_memcpy(&pending.event.addr[0],&sa6.sin6_addr.in6_u.u6_addr8,16);
  } else { return 0; }
  connecting.update(&tid,&pending); return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
  u64 tid=bpf_get_current_pid_tgid();
  struct pending_t *pending=connecting.lookup(&tid);
  if (!pending) return 0;
  pending->event.retval=args->ret;
  events.perf_submit(args,&pending->event,sizeof(pending->event));
  connecting.delete(&tid); return 0;
}
TRACEPOINT_PROBE(sched, sched_process_exec) {
  struct evt_t e = {}; identity(&e); e.kind=2;
  events.perf_submit(args,&e,sizeof(e)); return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
  struct file_evt_t e = {}; e.pid=bpf_get_current_pid_tgid()>>32;
  bpf_probe_read_user_str(&e.path,sizeof(e.path),(void *)args->filename);
  file_events.perf_submit(args,&e,sizeof(e)); return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_openat2) {
  struct file_evt_t e = {}; e.pid=bpf_get_current_pid_tgid()>>32;
  bpf_probe_read_user_str(&e.path,sizeof(e.path),(void *)args->filename);
  file_events.perf_submit(args,&e,sizeof(e)); return 0;
}
"""

def bcc_readiness()->tuple[bool,list[str]]:
    """Check the prerequisites BCC needs before attempting runtime compilation."""
    messages=[]
    if os.geteuid()!=0:
        messages.append("Igiris is not running as root; BCC cannot load eBPF programs.")
    if importlib.util.find_spec("bcc") is None:
        messages.append("BCC Python bindings are missing (install python3-bpfcc on Kali/Debian).")
    release=platform.uname().release
    build=Path("/lib/modules")/release/"build"
    kheaders=Path("/sys/kernel/kheaders.tar.xz")
    if not build.exists() and not kheaders.exists():
        messages.append(
            f"Matching kernel headers are unavailable: {build} does not exist and the kheaders interface is not active. "
            "Install the headers matching the running kernel, then reboot into that kernel if needed."
        )
    return not messages,messages

def bcc_available()->bool:
    return bcc_readiness()[0]

def capability_report()->dict:
    available,messages=bcc_readiness()
    return {"ebpf_available":available,"privileged":os.geteuid()==0,
        "messages":messages}

class BccCollector(PollingCollector):
    """Kernel connect, exec, and file-open history plus live /proc enrichment."""
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self._pending_paths:dict[int,set[str]]={}
        self._network_roots:dict[int,int]={}
    @staticmethod
    def _artifact_kind(path:str)->str:
        name=Path(path).name
        return "library" if ".so" in name and (name.endswith(".so") or ".so." in name) else "file"
    def _persist_kernel_paths(self,pid:int,root:int,paths:set[str]):
        if not paths: return
        now=datetime.now(timezone.utc)
        self.store.upsert_artifacts([ProcessArtifact(pid=pid,root_pid=root,kind=self._artifact_kind(path),path=path,
            source="ebpf_open",first_seen=now,last_seen=now) for path in paths])
    def _consume_file(self,cpu,data,size):
        raw=self._bpf["file_events"].event(data); pid=int(raw.pid)
        path=bytes(raw.path).split(b"\0",1)[0].decode(errors="replace")
        if not path: return
        root=self._network_roots.get(pid)
        if root is not None:
            self._persist_kernel_paths(pid,root,{path}); return
        paths=self._pending_paths.setdefault(pid,set())
        if len(paths)<256: paths.add(path)
        if len(self._pending_paths)>4096: self._pending_paths.pop(next(iter(self._pending_paths)))
    def _consume(self,cpu,data,size):
        raw=self._bpf["events"].event(data); pid=int(raw.pid); ppid=int(raw.ppid); kind=int(raw.kind)
        comm=bytes(raw.comm).split(b"\0",1)[0].decode(errors="replace") or f"pid-{pid}"
        table=snapshot_processes(); snap=table.get(pid) or ProcessSnapshot(pid,ppid,comm,None,comm,None); table.setdefault(pid,snap)
        root=resolve_root(pid,table); node=to_node(snap,root); persist_lineage(self.store,pid,table,root); persist_advanced_artifacts(self.store,pid,root)
        if kind==2:
            # A PID may have been reused. Opens following this exec belong to the new image.
            self._network_roots.pop(pid,None); self._pending_paths.pop(pid,None)
            if comm not in self.settings.network_tool_set: return
            self._network_roots[pid]=root
            self._persist_kernel_paths(pid,root,self._pending_paths.pop(pid,set()))
            self.store.add_event(Event(ts=datetime.now(timezone.utc),type="exec_network_tool",pid=pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
                family="ipv6" if comm=="ping6" else "unknown",domain_source="none",raw_meta={"tool":comm,"source":"ebpf_sched_exec"}))
            query=dns_query_from_tool(snap)
            if query:
                self.store.add_event(Event(ts=datetime.now(timezone.utc),type="dns",pid=pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
                    family="unknown",protocol="dns",domain=query,domain_source="observed_dns",raw_meta={"tool":comm,"source":"ebpf_sched_exec"}))
            return
        self._network_roots[pid]=root
        self._persist_kernel_paths(pid,root,self._pending_paths.pop(pid,set()))
        family="ipv6" if int(raw.family)==socket.AF_INET6 else "ipv4"
        packed=bytes(raw.addr)[:16 if family=="ipv6" else 4]
        try: address=socket.inet_ntop(socket.AF_INET6 if family=="ipv6" else socket.AF_INET,packed)
        except OSError: return
        domain,source=self.domains.lookup(pid,address)
        retval=int(raw.retval)
        success=True if retval==0 else None if retval==-115 else False
        self.store.add_event(Event(ts=datetime.now(timezone.utc),type="connect",pid=pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
            family=family,protocol="ip-connect",raddr=address,rport=socket.ntohs(int(raw.dport)),domain=domain,domain_source=source,
            success=success,raw_meta={"source":"ebpf_sys_connect","ppid":ppid,"retval":retval}))
    def _perf_loop(self):
        while not self.stop_event.is_set(): self._bpf.perf_buffer_poll(timeout=250)
    async def run(self):
        from bcc import BPF
        self._bpf=BPF(text=BPF_PROGRAM)
        self._bpf["events"].open_perf_buffer(self._consume,page_cnt=64)
        # Keep file-open traffic isolated so it cannot crowd connect/exec events out.
        self._bpf["file_events"].open_perf_buffer(self._consume_file,page_cnt=256)
        self._seen=set(snapshot_processes())
        self.status.update({"mode":"ebpf+bcc","visibility":"full","privileged":True,"ebpf_available":True,
            "messages":["Kernel-assisted IPv4/IPv6 connect, exec, and file-open capture active; DNS names and ICMP remain best-effort."]})
        perf=asyncio.create_task(asyncio.to_thread(self._perf_loop))
        try:
            while not self.stop_event.is_set():
                await asyncio.to_thread(self.collect_once); await asyncio.sleep(self.settings.poll_interval)
        finally:
            self.stop_event.set(); perf.cancel()
