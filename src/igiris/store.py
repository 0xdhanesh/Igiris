from __future__ import annotations
import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .models import Event, ParentSummary, ProcessArtifact, ProcessNode
from .processes import is_odd_path

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS processes (
 pid INTEGER PRIMARY KEY, ppid INTEGER NOT NULL, root_pid INTEGER NOT NULL, name TEXT NOT NULL,
 exe_path TEXT, exe_hash TEXT, user TEXT, cmdline TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_process_root ON processes(root_pid);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, type TEXT NOT NULL, pid INTEGER NOT NULL,
 root_pid INTEGER NOT NULL, exe_path TEXT, exe_hash TEXT, family TEXT NOT NULL, protocol TEXT,
 raddr TEXT, rport INTEGER, domain TEXT, domain_source TEXT NOT NULL, success INTEGER, raw_meta TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_event_root_ts ON events(root_pid, ts DESC);
CREATE INDEX IF NOT EXISTS idx_event_dest ON events(domain, raddr);
CREATE TABLE IF NOT EXISTS process_artifacts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, pid INTEGER NOT NULL, root_pid INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('library','file')), path TEXT NOT NULL, source TEXT NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 UNIQUE(root_pid,pid,kind,path)
);
CREATE INDEX IF NOT EXISTS idx_artifact_process ON process_artifacts(root_pid,pid,kind);
CREATE INDEX IF NOT EXISTS idx_artifact_path ON process_artifacts(path);
CREATE TABLE IF NOT EXISTS preferences (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

_EPOCH=datetime(1970,1,1,tzinfo=timezone.utc)
def _iso_micros(value:str)->int:
    parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
    if parsed.tzinfo is None: parsed=parsed.replace(tzinfo=timezone.utc)
    delta=parsed.astimezone(timezone.utc)-_EPOCH
    return (delta.days*86400+delta.seconds)*1_000_000+delta.microseconds

class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.create_function("iso_micros",1,_iso_micros,deterministic=True)
        os.chmod(self.path,0o600)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
    def initialize(self):
        with self.lock: self.conn.executescript(SCHEMA); self.conn.commit(); self._secure_files()
    def _secure_files(self):
        for path in (self.path,Path(str(self.path)+"-wal"),Path(str(self.path)+"-shm")):
            if path.exists(): os.chmod(path,0o600)
    def close(self): self.conn.close()
    def upsert_process(self, node: ProcessNode):
        values = node.model_dump(mode="json")
        with self.lock:
            self.conn.execute("""INSERT INTO processes(pid,ppid,root_pid,name,exe_path,exe_hash,user,cmdline,first_seen,last_seen)
            VALUES(:pid,:ppid,:root_pid,:name,:exe_path,:exe_hash,:user,:cmdline,:first_seen,:last_seen)
            ON CONFLICT(pid) DO UPDATE SET ppid=excluded.ppid,root_pid=excluded.root_pid,name=excluded.name,
            exe_path=COALESCE(excluded.exe_path,processes.exe_path),exe_hash=COALESCE(excluded.exe_hash,processes.exe_hash),
            user=COALESCE(excluded.user,processes.user),cmdline=excluded.cmdline,last_seen=excluded.last_seen""", values)
            self.conn.commit()
    def upsert_artifacts(self,artifacts:list[ProcessArtifact]):
        if not artifacts: return
        rows=[item.model_dump(mode="json",exclude={"id"}) for item in artifacts]
        with self.lock:
            self.conn.executemany("""INSERT INTO process_artifacts(pid,root_pid,kind,path,source,first_seen,last_seen)
                VALUES(:pid,:root_pid,:kind,:path,:source,:first_seen,:last_seen)
                ON CONFLICT(root_pid,pid,kind,path) DO UPDATE SET source=excluded.source,last_seen=excluded.last_seen""",rows)
            self.conn.commit()
    def list_artifacts(self,root_pid:int,pid:int)->list[ProcessArtifact]:
        with self.lock:
            rows=self.conn.execute("SELECT * FROM process_artifacts WHERE root_pid=? AND pid=? ORDER BY kind,path",(root_pid,pid)).fetchall()
        return [ProcessArtifact.model_validate(dict(row)) for row in rows]
    def _event_data(self,event:Event)->dict:
        data=event.model_dump(mode="json",exclude={"id"}); data["raw_meta"]=json.dumps(data["raw_meta"],separators=(",",":")); data["success"]=None if data["success"] is None else int(data["success"]); return data
    def _insert_event(self,event:Event):
        return self.conn.execute("""INSERT INTO events(ts,type,pid,root_pid,exe_path,exe_hash,family,protocol,raddr,rport,domain,domain_source,success,raw_meta)
            VALUES(:ts,:type,:pid,:root_pid,:exe_path,:exe_hash,:family,:protocol,:raddr,:rport,:domain,:domain_source,:success,:raw_meta)""",self._event_data(event))
    def add_event(self, event: Event) -> int:
        with self.lock:
            cur=self._insert_event(event); self.conn.commit(); return int(cur.lastrowid)
    def replace_live_events(self,events:list[Event]):
        with self.lock:
            self.conn.execute("DELETE FROM events WHERE type='live_socket'")
            for event in events:
                if event.type!="live_socket": raise ValueError("replace_live_events accepts only live_socket events")
                self._insert_event(event)
            self.conn.commit()
    def _event(self,row):
        data=dict(row); data["raw_meta"]=json.loads(data["raw_meta"] or "{}");
        if data["success"] is not None: data["success"]=bool(data["success"])
        return Event.model_validate(data)
    def list_events(self, root_pid:int|None=None, search:str|None=None, baseline_only:bool=False, limit:int=2000, mode:str="combined", process_pid:int|None=None) -> list[Event]:
        where=[]; args=[]
        if root_pid is not None: where.append("e.root_pid=?"); args.append(root_pid)
        if process_pid is not None: where.append("e.pid=?"); args.append(process_pid)
        if baseline_only and self.get_baseline(): where.append("iso_micros(e.ts)>iso_micros(?)"); args.append(self.get_baseline().isoformat())
        if mode=="live": where.append("e.type='live_socket'")
        elif mode=="history": where.append("e.type!='live_socket'")
        if search:
            q=f"%{search.lower()}%"; where.append("(lower(p.name) LIKE ? OR lower(p.exe_path) LIKE ? OR lower(p.exe_hash) LIKE ? OR lower(e.domain) LIKE ? OR lower(e.raddr) LIKE ?)"); args += [q]*5
        sql="SELECT e.* FROM events e LEFT JOIN processes p ON p.pid=e.pid"+(" WHERE "+" AND ".join(where) if where else "")+" ORDER BY e.ts DESC LIMIT ?"; args.append(limit)
        with self.lock: return [self._event(r) for r in self.conn.execute(sql,args).fetchall()]
    def list_processes(self, root_pid:int) -> list[ProcessNode]:
        with self.lock: rows=self.conn.execute("SELECT * FROM processes WHERE root_pid=? ORDER BY first_seen,pid",(root_pid,)).fetchall()
        return [ProcessNode.model_validate(dict(r)) for r in rows]
    def list_process_subtree(self,root_pid:int,pid:int)->list[ProcessNode]:
        processes=self.list_processes(root_pid)
        by_parent={}
        for process in processes: by_parent.setdefault(process.ppid,[]).append(process)
        result=[]; queue=[pid]; seen=set()
        while queue:
            current=queue.pop(0)
            if current in seen: continue
            seen.add(current)
            process=next((item for item in processes if item.pid==current),None)
            if process: result.append(process)
            queue.extend(child.pid for child in by_parent.get(current,[]))
        return result
    def _matching_root_pids(self,search:str)->set[int]:
        q=f"%{search.lower()}%"
        process_columns=("name","exe_path","exe_hash","user","cmdline")
        process_where=" OR ".join([f"lower(COALESCE({column},'')) LIKE ?" for column in process_columns]+["CAST(pid AS TEXT) LIKE ?","CAST(ppid AS TEXT) LIKE ?","CAST(root_pid AS TEXT) LIKE ?"])
        event_columns=("type","exe_path","exe_hash","family","protocol","raddr","domain","domain_source","raw_meta")
        event_where=" OR ".join([f"lower(COALESCE({column},'')) LIKE ?" for column in event_columns]+["CAST(pid AS TEXT) LIKE ?","CAST(root_pid AS TEXT) LIKE ?","CAST(rport AS TEXT) LIKE ?"])
        with self.lock:
            process_roots={int(row[0]) for row in self.conn.execute(f"SELECT DISTINCT root_pid FROM processes WHERE {process_where}",[q]*8)}
            event_roots={int(row[0]) for row in self.conn.execute(f"SELECT DISTINCT root_pid FROM events WHERE {event_where}",[q]*12)}
            artifact_roots={int(row[0]) for row in self.conn.execute("SELECT DISTINCT root_pid FROM process_artifacts WHERE lower(path) LIKE ? OR lower(source) LIKE ?",(q,q))}
        return process_roots|event_roots|artifact_roots
    def list_parents(self, search:str|None=None, baseline_only:bool=False) -> list[ParentSummary]:
        events=self.list_events(baseline_only=baseline_only,limit=100000)
        if search:
            matching_roots=self._matching_root_pids(search)
            events=[event for event in events if event.root_pid in matching_roots]
        roots={e.root_pid for e in events}; result=[]
        with self.lock:
            for root in roots:
                p=self.conn.execute("SELECT * FROM processes WHERE pid=?",(root,)).fetchone() or self.conn.execute("SELECT * FROM processes WHERE root_pid=? ORDER BY pid LIMIT 1",(root,)).fetchone()
                if not p: continue
                subset=[e for e in events if e.root_pid==root]; dests=[]
                for e in subset:
                    d=e.domain or e.raddr
                    if d and d not in dests: dests.append(d)
                result.append(ParentSummary(root_pid=root,pid=p["pid"],name=p["name"],user=p["user"],exe_path=p["exe_path"],exe_hash=p["exe_hash"],
                    live_connection_count=sum(e.type=="live_socket" for e in subset),history_event_count=sum(e.type!="live_socket" for e in subset),
                    latest_persistent_event_id=max((e.id or 0 for e in subset if e.type!="live_socket"),default=0),
                    unique_destination_count=len(dests),last_activity=max(e.ts for e in subset),top_destinations=dests[:6],odd_path=is_odd_path(p["exe_path"])))
        return sorted(result,key=lambda x:x.last_activity,reverse=True)
    def set_baseline(self, ts:datetime):
        with self.lock: self.conn.execute("INSERT INTO preferences(key,value) VALUES('baseline_ts',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(ts.isoformat(),)); self.conn.commit()
    def clear_baseline(self):
        with self.lock: self.conn.execute("DELETE FROM preferences WHERE key='baseline_ts'"); self.conn.commit()
    def get_baseline(self)->datetime|None:
        with self.lock: row=self.conn.execute("SELECT value FROM preferences WHERE key='baseline_ts'").fetchone()
        return datetime.fromisoformat(row[0]) if row else None
    def prune(self,retention_hours:int)->int:
        cutoff=(datetime.now(timezone.utc)-timedelta(hours=retention_hours)).isoformat()
        with self.lock:
            cur=self.conn.execute("DELETE FROM events WHERE ts<?",(cutoff,))
            self.conn.execute("DELETE FROM process_artifacts WHERE iso_micros(last_seen)<iso_micros(?)",(cutoff,))
            self.conn.commit(); return cur.rowcount
    def prune_to_cap(self,max_bytes:int)->int:
        """Soft-cap evidence by removing the oldest rows, then compacting SQLite."""
        files=(self.path,Path(str(self.path)+"-wal"),Path(str(self.path)+"-shm"))
        size=sum(p.stat().st_size for p in files if p.exists())
        if max_bytes<=0 or size<=max_bytes: return 0
        with self.lock:
            count=int(self.conn.execute("SELECT count(*) FROM events").fetchone()[0])
            if not count: return 0
            keep=max(0,min(count-1,int(count*(max_bytes/size)*0.8)))
            remove=count-keep
            self.conn.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY ts ASC LIMIT ?)",(remove,))
            self.conn.commit(); self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)"); self.conn.execute("VACUUM")
            return remove
    def data_revision(self)->str:
        with self.lock:
            persistent=int(self.conn.execute("SELECT COALESCE(MAX(id),0) FROM events WHERE type!='live_socket'").fetchone()[0])
            artifact_revision=int(self.conn.execute("SELECT COALESCE(MAX(id),0) FROM process_artifacts").fetchone()[0])
            rows=self.conn.execute("""SELECT pid,root_pid,exe_path,exe_hash,family,protocol,raddr,rport,domain,domain_source,success,raw_meta
                FROM events WHERE type='live_socket' ORDER BY pid,family,protocol,raddr,rport,domain""").fetchall()
        live=[list(row) for row in rows]
        payload=json.dumps([persistent,artifact_revision,live],separators=(",",":"),ensure_ascii=True).encode()
        return hashlib.sha256(payload).hexdigest()[:24]
    def clear_all_evidence(self)->dict[str,int]:
        with self.lock:
            counts={"events":int(self.conn.execute("SELECT count(*) FROM events").fetchone()[0]),"processes":int(self.conn.execute("SELECT count(*) FROM processes").fetchone()[0]),"artifacts":int(self.conn.execute("SELECT count(*) FROM process_artifacts").fetchone()[0])}
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                self.conn.execute("DELETE FROM events")
                self.conn.execute("DELETE FROM process_artifacts")
                self.conn.execute("DELETE FROM processes")
                self.conn.execute("DELETE FROM preferences WHERE key='baseline_ts'")
                self.conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('events','process_artifacts')")
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._secure_files()
            return counts
    def clear_live_events(self):
        self.replace_live_events([])
