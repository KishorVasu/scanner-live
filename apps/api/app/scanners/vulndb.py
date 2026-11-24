"""Daily refresh of the offline vulnerability DBs (OSV, Trivy) used by the offline scanners (SCANNING_STRATEGY §4.2).

The worker only asks scan-runner to run the fixed sync jobs; it has no egress for this and passes no URLs. Each
outcome is audited. A failed sync keeps the previous DB; scans fail once it is older than 48 hours.
"""

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models import ActorType
from app.modules.audit.service import record

DBS = ("osv", "trivy")
_transport: httpx.AsyncBaseTransport | None = None  # tests inject a MockTransport


async def sync_all(db: AsyncSession) -> dict[str, bool]:
    results: dict[str, bool] = {}
    async with httpx.AsyncClient(base_url=get_settings().scan_runner_url, timeout=1000, transport=_transport) as c:
        for name in DBS:
            try:
                r = await c.post("/sync", json={"db": name})
                body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                ok = r.status_code == 200 and body.get("ok") is True
                error = None if ok else str(body.get("error") or f"scan-runner answered {r.status_code}")[:300]
            except httpx.HTTPError as e:
                ok, error = False, f"scan-runner unreachable: {type(e).__name__}"
            results[name] = ok
            record(db, actor_type=ActorType.system, actor_id="beat", action="vulndb.sync",
                   outcome="success" if ok else "failure", target_type="vulndb", target_id=name,
                   detail=None if ok else {"error": error})
    await db.commit()
    return results
