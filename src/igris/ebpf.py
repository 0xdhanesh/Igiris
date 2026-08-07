from __future__ import annotations
import asyncio, importlib.util, os, platform, socket
from pathlib import Path
from datetime import datetime, timezone
from .collectors import (
    PollingCollector, _intent_target, _looks_ip, dns_query_from_tool,
    observed_domain_from_tool, persist_advanced_artifacts, persist_lineage,
)
from .models import Event, ProcessArtifact
from .processes import ProcessSnapshot, resolve_root, snapshot_processes, to_node

# BCC program for connect/exec telemetry. DNS and ICMP enrichers remain best-effort and
# use the shared event schema; deployments without BCC fall back to /proc polling.
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <linux/sched.h>
struct evt_t { u32 pid; u32 ppid; u32 kind; s32 retval; u16 family; u16 dport; unsigned char addr[16]; char comm[16]; s32 stack_id; };
struct file_evt_t { u32 pid; u32 ppid; char path[256]; };
struct exec_evt_t { u32 pid; u32 ppid; s32 stack_id; char path[256]; };
struct pending_t { struct evt_t event; };
BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(file_events);
BPF_PERF_OUTPUT(exec_events);
BPF_HASH(connecting, u64, struct pending_t);
BPF_HASH(network_tool_pids, u32, u8);
BPF_STACK_TRACE(user_stacks, 16384);
static int network_tool(char *c) {
  if (c[0]=='p' && c[1]=='i' && c[2]=='n' && c[3]=='g' && (c[4]=='\0' || (c[4]=='6' && c[5]=='\0'))) return 1;
  if (c[0]=='c' && c[1]=='u' && c[2]=='r' && c[3]=='l' && c[4]=='\0') return 1;
  if (c[0]=='w' && c[1]=='g' && c[2]=='e' && c[3]=='t' && c[4]=='\0') return 1;
  if (c[0]=='d' && c[1]=='i' && c[2]=='g' && c[3]=='\0') return 1;
  if (c[0]=='h' && c[1]=='o' && c[2]=='s' && c[3]=='t' && c[4]=='\0') return 1;
  if (c[0]=='s' && c[1]=='s' && c[2]=='h' && c[3]=='\0') return 1;
  if (c[0]=='n' && c[1]=='c' && c[2]=='\0') return 1;
  if (c[0]=='n' && c[1]=='c' && c[2]=='a' && c[3]=='t' && c[4]=='\0') return 1;
  if (c[0]=='n' && c[1]=='s' && c[2]=='l' && c[3]=='o' && c[4]=='o' && c[5]=='k' && c[6]=='u' && c[7]=='p' && c[8]=='\0') return 1;
  return 0;
}
static int shared_object(char *path) {
  int found=0;
  #pragma unroll
  for (int i=0;i<253;i++) {
    if (path[i]=='.' && path[i+1]=='s' && path[i+2]=='o') found=1;
  }
  return found;
}
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
  struct pending_t pending={}; identity(&pending.event); pending.event.kind=1; pending.event.family=family; pending.event.stack_id=-1;
  pending.event.stack_id = user_stacks.get_stackid(args, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
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
  if (network_tool(e.comm)) {
    u8 one=1;
    network_tool_pids.update(&e.pid,&one);
  } else network_tool_pids.delete(&e.pid);
  events.perf_submit(args,&e,sizeof(e)); return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
  struct exec_evt_t e = {};
  e.pid=bpf_get_current_pid_tgid()>>32;
  struct task_struct *task=(struct task_struct *)bpf_get_current_task();
  bpf_probe_read_kernel(&e.ppid,sizeof(e.ppid),&task->real_parent->tgid);
  e.stack_id=user_stacks.get_stackid(args,BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
  bpf_probe_read_user_str(&e.path,sizeof(e.path),(void *)args->filename);
  exec_events.perf_submit(args,&e,sizeof(e)); return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
  struct file_evt_t e = {}; e.pid=bpf_get_current_pid_tgid()>>32;
  bpf_probe_read_user_str(&e.path,sizeof(e.path),(void *)args->filename);
  if (!network_tool_pids.lookup(&e.pid) && !shared_object(e.path)) return 0;
  file_events.perf_submit(args,&e,sizeof(e)); return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_openat2) {
  struct file_evt_t e = {}; e.pid=bpf_get_current_pid_tgid()>>32;
  bpf_probe_read_user_str(&e.path,sizeof(e.path),(void *)args->filename);
  if (!network_tool_pids.lookup(&e.pid) && !shared_object(e.path)) return 0;
  file_events.perf_submit(args,&e,sizeof(e)); return 0;
}
"""

def bcc_readiness()->tuple[bool,list[str]]:
    """Check the prerequisites BCC needs before attempting runtime compilation."""
    messages=[]
    if os.geteuid()!=0:
        messages.append("Igris is not running as root; BCC cannot load eBPF programs.")
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
    """Kernel connect, exec, and file-open history plus live /proc enrichment. Now with user-space stack tracing for call-site attribution (v1.0)."""
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self._pending_paths:dict[int,set[str]]={}
        self._network_roots:dict[int,int]={}
        self._exec_roots:dict[int,int]={}
        self._exec_provenance:dict[int,dict]={}
    @staticmethod
    def _artifact_kind(path:str)->str:
        name=Path(path).name
        return "library" if ".so" in name and (name.endswith(".so") or ".so." in name) else "file"
    @staticmethod
    def _decode_symbol_part(value):
        return value.decode(errors="replace") if isinstance(value,bytes) else value
    @staticmethod
    def _exec_caller(stack_trace:list[dict])->dict|None:
        runtime_prefixes=("libc.so","libpthread.so","ld-linux","ld-musl")
        resolved=[frame for frame in stack_trace if frame.get("library")]
        return next((frame for frame in resolved
            if not Path(str(frame["library"])).name.startswith(runtime_prefixes)),resolved[0] if resolved else None)
    def _resolve_stack_trace(self,pid:int,stack_id:int)->list[dict]:
        """Resolve an ordered user stack while the process mappings still exist."""
        if stack_id < 0:
            return []
        try:
            cache=self._bpf._sym_cache(pid)
            frames=[]
            for address in self._bpf["user_stacks"].walk(stack_id):
                symbol,offset,module=cache.resolve(int(address),True)
                frames.append({
                    "library":self._decode_symbol_part(module),
                    "symbol":self._decode_symbol_part(symbol),
                    "offset":hex(int(offset)),
                    "raw_ip":hex(int(address)),
                })
            return frames
        except Exception:
            return []
    def _persist_kernel_paths(self,pid:int,root:int,paths:set[str],source:str="ebpf_open_network_active"):
        if not paths: return
        now=datetime.now(timezone.utc)
        self.store.upsert_artifacts([ProcessArtifact(pid=pid,root_pid=root,kind=self._artifact_kind(path),path=path,
            source=source,first_seen=now,last_seen=now) for path in paths])
    def _event_root(self,pid:int,ppid:int,kind:int,table:dict[int,ProcessSnapshot])->int:
        if kind==2:
            self._network_roots.pop(pid,None)
            root=self._exec_roots.get(ppid) or resolve_root(pid,table)
            self._exec_roots[pid]=root
            if len(self._exec_roots)>65536:
                self._exec_roots.pop(next(iter(self._exec_roots)))
            return root
        return self._network_roots.get(pid) or resolve_root(pid,table)
    def _consume_file(self,cpu,data,size):
        raw=self._bpf["file_events"].event(data); pid=int(raw.pid)
        path=bytes(raw.path).split(b"\0",1)[0].decode(errors="replace")
        if not path: return
        root=self._network_roots.get(pid) or self._exec_roots.get(pid)
        if root is not None:
            source="ebpf_open_network_active" if pid in self._network_roots else "ebpf_open_exec_observed"
            self._persist_kernel_paths(pid,root,{path},source); return
        paths=self._pending_paths.setdefault(pid,set())
        if len(paths)<256: paths.add(path)
        if len(self._pending_paths)>4096: self._pending_paths.pop(next(iter(self._pending_paths)))
    def _consume_exec_intent(self,cpu,data,size):
        raw=self._bpf["exec_events"].event(data)
        pid=int(raw.pid); ppid=int(raw.ppid); stack_id=int(raw.stack_id)
        path=bytes(raw.path).split(b"\0",1)[0].decode(errors="replace")
        # Before exec, a forked child shares the parent's mappings. Resolve the
        # child's user stack against the still-running parent before ping replaces
        # that address space.
        stack_trace=self._resolve_stack_trace(ppid,stack_id)
        caller=self._exec_caller(stack_trace)
        call_site=({
            **caller,
            "source":"bpf_execve_parent_stack_v1",
            "resolution":"top_resolved_exec_caller_frame",
        } if caller else None)
        self._exec_provenance[pid]={"exec_path":path,"exec_parent_pid":ppid,
            "exec_stack_id":stack_id,"exec_stack_trace":stack_trace,"exec_call_site":call_site}
        parent_root=self._exec_roots.get(ppid)
        if parent_root is not None:
            persist_advanced_artifacts(self.store,ppid,parent_root)
            modules={frame["library"] for frame in stack_trace
                if frame.get("library") and str(frame["library"]).startswith("/")}
            self._persist_kernel_paths(ppid,parent_root,modules,"ebpf_execve_caller_stack")
        if len(self._exec_provenance)>8192:
            self._exec_provenance.pop(next(iter(self._exec_provenance)))
    def _consume(self,cpu,data,size):
        raw=self._bpf["events"].event(data); pid=int(raw.pid); ppid=int(raw.ppid); kind=int(raw.kind)
        comm=bytes(raw.comm).split(b"\0",1)[0].decode(errors="replace") or f"pid-{pid}"
        stack_id = int(getattr(raw, 'stack_id', -1))
        table=snapshot_processes(); snap=table.get(pid) or ProcessSnapshot(pid,ppid,comm,None,comm,None); table.setdefault(pid,snap)
        # Exec starts a new process-image lifetime. Later connect callbacks can be
        # delayed until after a short-lived tool and its parent have exited, so
        # retain this root instead of recomputing a different one from a partial
        # /proc snapshot and orphaning the already-persisted events.
        root=self._event_root(pid,ppid,kind,table)
        node=to_node(snap,root); persist_lineage(self.store,pid,table,root); persist_advanced_artifacts(self.store,pid,root)
        if kind==2:
            # Perf buffers are independent, so an open emitted after exec can be
            # delivered before the sched-exec callback. Preserve those paths
            # against the newly established process lifetime.
            pending_paths=self._pending_paths.pop(pid,set())
            self._persist_kernel_paths(pid,root,pending_paths,"ebpf_open_near_exec")
            provenance=self._exec_provenance.pop(pid,{})
            if comm not in self.settings.network_tool_set: return
            self._network_roots[pid]=root
            domain,domain_source=observed_domain_from_tool(snap)
            self.store.add_event(Event(ts=datetime.now(timezone.utc),type="exec_network_tool",pid=pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
                family="ipv6" if comm=="ping6" else "unknown",domain=domain,domain_source=domain_source,
                raw_meta={"tool":comm,"cmdline":snap.cmdline,"source":"ebpf_sched_exec",**provenance}))
            query=dns_query_from_tool(snap)
            if query:
                self.store.add_event(Event(ts=datetime.now(timezone.utc),type="dns",pid=pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
                    family="unknown",protocol="dns",domain=query,domain_source="observed_dns",raw_meta={"tool":comm,"source":"ebpf_sched_exec"}))
            if comm in {"ping","ping6"}:
                target=_intent_target(snap.cmdline)
                self.store.add_event(Event(ts=datetime.now(timezone.utc),type="icmp",pid=pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
                    family="ipv6" if comm=="ping6" else "ipv4",protocol="icmpv6" if comm=="ping6" else "icmp",
                    raddr=target if target and _looks_ip(target) else None,domain=domain,domain_source=domain_source,
                    raw_meta={"best_effort":True,"target_argument":target,"source":"ebpf_sched_exec",**provenance}))
            return
        self._network_roots[pid]=root
        self._persist_kernel_paths(pid,root,self._pending_paths.pop(pid,set()),"ebpf_open_before_connect")
        family="ipv6" if int(raw.family)==socket.AF_INET6 else "ipv4"
        packed=bytes(raw.addr)[:16 if family=="ipv6" else 4]
        try: address=socket.inet_ntop(socket.AF_INET6 if family=="ipv6" else socket.AF_INET,packed)
        except OSError: return
        domain,source=self.domains.lookup(pid,address)
        retval=int(raw.retval)
        success=True if retval==0 else None if retval==-115 else False
        stack_trace=self._resolve_stack_trace(pid,stack_id)
        call_site=next(({
            **frame,
            "source":"bpf_stack_trace_user_v1",
            "resolution":"top_resolved_user_frame",
        } for frame in stack_trace if frame.get("library")),None)
        raw_meta = {
            "source": "ebpf_sys_connect",
            "ppid": ppid,
            "retval": retval,
            "call_site": call_site,
            "stack_id": stack_id,
            "stack_trace": stack_trace,
        }
        if call_site:
            raw_meta["call_site_source"] = "user_space_stack_v1.0"
        self.store.add_event(Event(ts=datetime.now(timezone.utc),type="connect",pid=pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
            family=family,protocol="ip-connect",raddr=address,rport=socket.ntohs(int(raw.dport)),domain=domain,domain_source=source,
            success=success,raw_meta=raw_meta))
    def _perf_loop(self):
        while not self.stop_event.is_set(): self._bpf.perf_buffer_poll(timeout=250)
    async def run(self):
        from bcc import BPF
        self._bpf=BPF(text=BPF_PROGRAM)
        self._bpf["user_stacks"] = self._bpf.get_table("user_stacks")
        self._bpf["events"].open_perf_buffer(self._consume,page_cnt=64)
        self._bpf["exec_events"].open_perf_buffer(self._consume_exec_intent,page_cnt=64)
        # Keep file-open traffic isolated so it cannot crowd connect/exec events out.
        self._bpf["file_events"].open_perf_buffer(self._consume_file,page_cnt=256)
        self._seen=set(snapshot_processes())
        self.status.update({"mode":"ebpf+bcc+userstack","visibility":"full","privileged":True,"ebpf_available":True,
            "messages":["Kernel-assisted IPv4/IPv6 connect with v1.0 user-space stack tracing for precise call-site (library+offset). Temporal correlation remains as fallback."]})
        perf=asyncio.create_task(asyncio.to_thread(self._perf_loop))
        try:
            while not self.stop_event.is_set():
                await asyncio.to_thread(self.collect_once); await asyncio.sleep(self.settings.poll_interval)
        finally:
            self.stop_event.set(); perf.cancel()
