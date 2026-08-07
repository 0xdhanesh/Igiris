from __future__ import annotations
import asyncio
import sys
from contextlib import asynccontextmanager
import uvicorn
from .api import create_app
from .collectors import PollingCollector
from .ebpf import BccCollector, bcc_readiness
from .config import Settings
from .store import Store

def build_app(settings:Settings|None=None):
    settings=settings or Settings(); store=Store(settings.database_path); store.initialize(); collector=None; task=None
    async def _run_collector(app):
        nonlocal collector
        ready,diagnostics=bcc_readiness()
        if diagnostics:
            app.state.collector_status["messages"]=diagnostics
        collector=(BccCollector if ready else PollingCollector)(store,settings,app.state.collector_status)
        try:
            await collector.run()
        except Exception as exc:
            if isinstance(collector,PollingCollector) and not isinstance(collector,BccCollector):
                raise
            app.state.collector_status.update({"mode":"proc-polling","visibility":"limited","ebpf_available":False,
                "messages":[f"eBPF initialization failed: {exc}","Falling back to /proc socket and process polling."]})
            collector=PollingCollector(store,settings,app.state.collector_status)
            await collector.run()
    @asynccontextmanager
    async def lifespan(app):
        nonlocal collector,task
        if settings.collector_enabled:
            task=asyncio.create_task(_run_collector(app))
        yield
        if collector: collector.stop()
        if task: task.cancel()
        store.close()
    app=create_app(settings,store)
    app.state.reset_collector_tracking=lambda: collector.reset_tracking() if collector else None
    app.router.lifespan_context=lifespan
    return app

def run():
    settings = Settings()
    host = settings.resolved_bind_host
    print(f"Starting Igris on {host}:{settings.bind_port}", file=sys.stderr, flush=True)
    uvicorn.run(build_app(settings), host=host, port=settings.bind_port)

app=build_app()
