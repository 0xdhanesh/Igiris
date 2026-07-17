from __future__ import annotations
import asyncio, importlib.util, os, socket
from datetime import datetime, timezone
from .collectors import PollingCollector, dns_query_from_tool, persist_advanced_artifacts, persist_lineage
from .models import Event
from .processes import ProcessSnapshot, resolve_root, snapshot_processes, to_node

# BCC program for connect/exec telemetry. DNS and ICMP enrichers remain best-effort and
# use the shared event schema; deployments without BCC fall back to /proc polling.
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <linux/sched.h>
struct evt_t { u32 pid; u32 ppid; u32 kind; s32 retval; u16 family; u16 dport; unsigned char addr[16]; char comm[16]; };
struct pending_t { struct evt_t event; };
BPF_PERF_OUTPUT(events);
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
"""

def bcc_available()->bool:
    return os.geteuid()==0 and importlib.util.find_spec("bcc") is not None

def capability_report()->dict:
    available=bcc_available()
    return {"ebpf_available":available,"privileged":os.geteuid()==0,
        "messages":[] if available else ["Install BCC Python bindings and run with root/CAP_BPF privileges for kernel-assisted connect and exec telemetry."]}

class BccCollector(PollingCollector):
    """Kernel-assisted connect/exec history plus /proc live-socket snapshots."""
    def _consume(self,cpu,data,size):
        raw=self._bpf["events"].event(data); pid=int(raw.pid); ppid=int(raw.ppid); kind=int(raw.kind)
        comm=bytes(raw.comm).split(b"\0",1)[0].decode(errors="replace") or f"pid-{pid}"
        table=snapshot_processes(); snap=table.get(pid) or ProcessSnapshot(pid,ppid,comm,None,comm,None); table.setdefault(pid,snap)
        root=resolve_root(pid,table); node=to_node(snap,root); persist_lineage(self.store,pid,table,root); persist_advanced_artifacts(self.store,pid,root)
        if kind==2:
            if comm not in self.settings.network_tool_set: return
            self.store.add_event(Event(ts=datetime.now(timezone.utc),type="exec_network_tool",pid=pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
                family="ipv6" if comm=="ping6" else "unknown",domain_source="none",raw_meta={"tool":comm,"source":"ebpf_sched_exec"}))
            query=dns_query_from_tool(snap)
            if query:
                self.store.add_event(Event(ts=datetime.now(timezone.utc),type="dns",pid=pid,root_pid=root,exe_path=node.exe_path,exe_hash=node.exe_hash,
                    family="unknown",protocol="dns",domain=query,domain_source="observed_dns",raw_meta={"tool":comm,"source":"ebpf_sched_exec"}))
            return
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
        self._seen=set(snapshot_processes())
        self.status.update({"mode":"ebpf+bcc","visibility":"full","privileged":True,"ebpf_available":True,
            "messages":["Kernel-assisted IPv4/IPv6 connect syscall and exec capture active; DNS names and ICMP remain best-effort."]})
        perf=asyncio.create_task(asyncio.to_thread(self._perf_loop))
        try:
            while not self.stop_event.is_set():
                await asyncio.to_thread(self.collect_once); await asyncio.sleep(self.settings.poll_interval)
        finally:
            self.stop_event.set(); perf.cancel()
