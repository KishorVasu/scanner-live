"""Prometheus metrics (Phase 6). Labels carry only fixed enums and route templates: never project names, paths,
user input or IDs, so a scrape can never leak repository data and label cardinality stays bounded.

The worker runs Celery's prefork pool, so it sets PROMETHEUS_MULTIPROC_DIR and serves the merged view from its main
process (see app/workers/celery_app.py). The API is a single process and uses the default registry.
"""

import os
import time

from prometheus_client import CollectorRegistry, Counter, Histogram, multiprocess, start_http_server

HTTP_SECONDS = Histogram("sp_http_request_seconds", "API request duration", ["method", "route", "status"])
SCAN_JOBS = Counter("sp_scan_jobs_total", "Scan jobs finished", ["scanner", "status"])
AGENT_RUNS = Counter("sp_agent_runs_total", "Agent runs finished", ["agent", "status"])
LLM_TOKENS = Counter("sp_llm_tokens_total", "LLM tokens used", ["agent", "direction"])
TASKS = Counter("sp_celery_tasks_total", "Celery tasks finished", ["task", "state"])


async def http_middleware(request, call_next):
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        route = request.scope.get("route")
        # Unmatched paths share one label, so scanners of the API cannot create new series.
        HTTP_SECONDS.labels(request.method, getattr(route, "path", "unmatched"), str(status)).observe(
            time.perf_counter() - start)


def serve_worker_metrics(port: int = 9100) -> None:
    """Expose the merged multiprocess metrics of the worker's pool children (main process only)."""
    path = os.environ.get("PROMETHEUS_MULTIPROC_DIR")
    if not path:
        return
    os.makedirs(path, exist_ok=True)
    for f in os.listdir(path):  # stale files from a previous container start would double-count
        os.remove(os.path.join(path, f))
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)
    start_http_server(port, registry=registry)
