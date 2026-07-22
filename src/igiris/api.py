from __future__ import annotations
import csv, io, json, os, threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .auth import LoginLimiter, SessionManager, verify_password
from .config import Settings
from .store import Store

EXPORT_FIELDS=["ts","type","pid","root_pid","exe_path","exe_hash","family","protocol","raddr","rport","domain","domain_source","success","raw_meta"]
CSV_FORMULA_PREFIXES=("=","+","-","@")

def _safe_csv_cell(value):
    if not isinstance(value,str): return value
    stripped=value.lstrip()
    if value.startswith(("\t","\r","\n")) or (stripped and stripped.startswith(CSV_FORMULA_PREFIXES)):
        return "'"+value
    return value

class LoginRequest(BaseModel):
    password: str = Field(min_length=1,max_length=1024)

def create_app(settings:Settings|None=None, store:Store|None=None)->FastAPI:
    settings=settings or Settings(); db=store or Store(settings.database_path); db.initialize()
    app=FastAPI(title="Igiris",version="0.1.0")
    verifier=settings.resolve_password_verifier(); sessions=SessionManager(settings.session_ttl_seconds); login_limiter=LoginLimiter(settings.login_max_failures,settings.login_failure_window_seconds); password_check_slots=threading.BoundedSemaphore(settings.login_max_parallel_checks); allowed_hosts=settings.allowed_host_list; allowed_origin_hosts={host.strip("[]") for host in allowed_hosts}
    def is_api_path(path:str)->bool: return path=="/api" or path.startswith("/api/")
    @app.exception_handler(Exception)
    async def unhandled_error(request:Request,_error:Exception):
        headers={"Cache-Control":"no-store"} if is_api_path(request.url.path) else None
        return JSONResponse({"detail":"Internal server error"},status_code=500,headers=headers)
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=allowed_hosts)
    @app.middleware("http")
    async def protect_local_api(request:Request,call_next):
        is_api=is_api_path(request.url.path)
        response=None
        if is_api:
            origin=request.headers.get("origin")
            if origin:
                try: origin_host=urlparse(origin).hostname
                except ValueError: origin_host=None
                if origin_host not in allowed_origin_hosts:
                    response=JSONResponse({"detail":"Origin not allowed"},status_code=403)
            if response is None and verifier and request.url.path != "/api/auth/login":
                supplied=request.headers.get("authorization","")
                scheme,separator,credential=supplied.partition(" ")
                if not separator or scheme != "Bearer" or not sessions.authenticate(credential):
                    response=JSONResponse({"detail":"Password session required"},status_code=401,headers={"WWW-Authenticate":"Bearer"})
        if response is None:
            response=await call_next(request)
        if is_api:
            response.headers["Cache-Control"]="no-store"
        return response
    app.state.settings=settings; app.state.store=db; app.state.sessions=sessions; app.state.collector_status={"mode":"disabled" if not settings.collector_enabled else "initializing","visibility":"limited","privileged":os.geteuid()==0,"ebpf_available":False,"messages":[]}
    @app.post("/api/auth/login")
    def login(payload:LoginRequest,request:Request):
        if not verifier: raise HTTPException(503,"Password authentication is not configured")
        client=request.client.host if request.client else "unknown"
        if not password_check_slots.acquire(blocking=False):
            raise HTTPException(429,"Password verification is busy",headers={"Retry-After":"1"})
        try:
            retry_after=login_limiter.reserve(client)
            if retry_after is not None:
                raise HTTPException(429,"Too many failed login attempts",headers={"Retry-After":str(retry_after)})
            if not verify_password(payload.password,verifier):
                raise HTTPException(401,"Invalid password")
            login_limiter.clear(client)
            return JSONResponse({"token":sessions.issue(),"expires_in":settings.session_ttl_seconds},headers={"Cache-Control":"no-store"})
        finally:
            password_check_slots.release()
    @app.post("/api/auth/logout",status_code=204)
    def logout(request:Request):
        sessions.revoke(request.headers.get("authorization","").removeprefix("Bearer "))
        return Response(status_code=204)
    @app.get("/api/health")
    def health(): return {"status":"ok",**app.state.collector_status,"retention_hours":settings.retention_hours,"baseline_ts":db.get_baseline()}
    @app.get("/api/revision")
    def revision(): return {"revision":db.data_revision()}
    @app.get("/api/parents")
    def parents(search:str|None=None,baseline_only:bool=False): return db.list_parents(search,baseline_only)
    @app.get("/api/parents/{root_pid}")
    def detail(root_pid:int,mode:str=Query("combined",pattern="^(live|history|combined)$"),destination:str|None=None,baseline_only:bool=False):
        summaries=[p for p in db.list_parents(baseline_only=baseline_only) if p.root_pid==root_pid]
        if not summaries: raise HTTPException(404,"Parent not found")
        events=db.list_events(root_pid=root_pid,baseline_only=baseline_only,mode=mode)
        if destination: events=[e for e in events if e.domain==destination or e.raddr==destination]
        return {"parent":summaries[0],"processes":db.list_processes(root_pid),"events":events,"baseline_ts":db.get_baseline()}
    @app.get("/api/events")
    def events(search:str|None=None,root_pid:int|None=None,pid:int|None=None,baseline_only:bool=False,mode:str=Query("combined",pattern="^(live|history|combined)$"),destination:str|None=None,limit:int=Query(500,ge=1,le=2000)):
        evidence=db.list_events(root_pid,search,baseline_only,limit=limit,mode=mode,process_pid=pid)
        return [event for event in evidence if not destination or event.domain==destination or event.raddr==destination]
    @app.get("/api/parents/{root_pid}/processes/{pid}/advanced")
    def advanced_process(root_pid:int,pid:int):
        processes=db.list_processes(root_pid); process=next((item for item in processes if item.pid==pid),None)
        if process is None: raise HTTPException(404,"Process not found in parent lineage")
        artifacts=db.list_artifacts(root_pid,pid)
        status=app.state.collector_status
        return {"process":process,"commands":db.list_process_subtree(root_pid,pid),
            "libraries":[item for item in artifacts if item.kind=="library"],
            "files":[item for item in artifacts if item.kind=="file"],
            "network":db.list_events(root_pid=root_pid,limit=2000,mode="combined",process_pid=pid),
            "collector":{"mode":status.get("mode"),"visibility":status.get("visibility"),"ebpf_available":status.get("ebpf_available",False)},
            "evidence_semantics":{"library_visibility":"kernel_events" if status.get("ebpf_available") else "observed_snapshot",
                "file_visibility":"kernel_events" if status.get("ebpf_available") else "observed_snapshot",
                "network_visibility":"kernel_assisted" if status.get("ebpf_available") else "observed_snapshot",
                "warning":("File and library paths are captured from eBPF open events, with /proc snapshots used only for enrichment."
                    if status.get("ebpf_available") else
                    "Library and file paths are observed from /proc snapshots for network-active processes; short-lived activity can be missed.")}}
    @app.post("/api/baseline")
    def set_baseline(payload:dict|None=None):
        raw=(payload or {}).get("baseline_ts"); ts=datetime.fromisoformat(raw.replace("Z","+00:00")) if raw else datetime.now(timezone.utc); db.set_baseline(ts); return {"baseline_ts":ts}
    @app.delete("/api/baseline")
    def clear_baseline(): db.clear_baseline(); return {"baseline_ts":None}
    @app.delete("/api/evidence")
    def clear_evidence():
        cleared=db.clear_all_evidence()
        reset=getattr(app.state,"reset_collector_tracking",None)
        if callable(reset): reset()
        return {"cleared":cleared}
    def selected(root_pid,search,baseline_only,mode,destination):
        evidence=db.list_events(root_pid,search,baseline_only,mode=mode,limit=100000)
        return [event for event in evidence if not destination or event.domain==destination or event.raddr==destination]
    @app.get("/api/export.json")
    def export_json(root_pid:int|None=None,search:str|None=None,baseline_only:bool=False,mode:str=Query("combined",pattern="^(live|history|combined)$"),destination:str|None=None):
        payload=[e.model_dump(mode="json") for e in selected(root_pid,search,baseline_only,mode,destination)]
        return StreamingResponse(io.BytesIO(json.dumps(payload,indent=2).encode()),media_type="application/json",headers={"Content-Disposition":"attachment; filename=igiris-evidence.json"})
    @app.get("/api/export.csv")
    def export_csv(root_pid:int|None=None,search:str|None=None,baseline_only:bool=False,mode:str=Query("combined",pattern="^(live|history|combined)$"),destination:str|None=None):
        out=io.StringIO(); writer=csv.DictWriter(out,fieldnames=EXPORT_FIELDS); writer.writeheader()
        for e in selected(root_pid,search,baseline_only,mode,destination):
            row=e.model_dump(mode="json",exclude={"id"}); row["raw_meta"]=json.dumps(row["raw_meta"],separators=(",",":")); writer.writerow({key:_safe_csv_cell(value) for key,value in row.items()})
        return StreamingResponse(io.BytesIO(out.getvalue().encode()),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=igiris-evidence.csv"})
    static=Path(settings.static_dir)
    if static.exists():
        app.mount("/assets",StaticFiles(directory=static/"assets"),name="assets")
        @app.get("/{path:path}",response_class=HTMLResponse)
        def spa(path:str): return (static/"index.html").read_text()
    return app
