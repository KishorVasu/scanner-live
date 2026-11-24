"""Allowlisted advisory fetchers (rule: allowlisted URLs only). Data only; no LLM here.

- OSV: `/v1/querybatch` does the version-range matching for every inventory package (decision 4: no home-grown range
  evaluators), `/v1/vulns/{id}` gives the record. OSV already aggregates GHSA for npm/PyPI/Packagist/Maven/Go/etc.,
  so GHSA records arrive through OSV with their GHSA IDs.
  ponytail: no direct GitHub advisory API fetch; add one only if a GHSA field we need is missing from OSV.
- CISA KEV: the published JSON catalogue, for `known_exploited`.
- NVD: CVSS for a CVE when OSV carries no severity.

Every request goes to an allowlisted https host with redirects off; the worker reaches them through its fetch proxy.
"""

import re
from datetime import datetime
from typing import Any

import httpx

from app.scanners.base import severity_from_cvss, severity_from_word

ALLOWED_HOSTS = frozenset({"api.osv.dev", "www.cisa.gov", "services.nvd.nist.gov"})
OSV_API = "https://api.osv.dev/v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_FACTS = 20_000
BATCH = 1000  # OSV querybatch limit
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")

transport: httpx.AsyncBaseTransport | None = None  # tests inject a MockTransport


class SourceError(Exception):
    pass


async def _guard(request: httpx.Request) -> None:
    if request.url.scheme != "https" or request.url.host not in ALLOWED_HOSTS:
        raise SourceError(f"host not allowlisted: {request.url.host}")


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=30, follow_redirects=False, transport=transport,
                             event_hooks={"request": [_guard]}, headers={"User-Agent": "security-platform"})


async def osv_matches(c: httpx.AsyncClient, queries: list[tuple[str, str, str]]) -> list[list[str]]:
    """For each (ecosystem, package, version): the OSV IDs that affect that exact version."""
    out: list[list[str]] = []
    for i in range(0, len(queries), BATCH):
        chunk = queries[i:i + BATCH]
        body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        r = await c.post(f"{OSV_API}/querybatch", json=body)
        r.raise_for_status()
        results = r.json().get("results") or []
        if len(results) != len(chunk):
            raise SourceError("OSV querybatch returned a different number of results")
        # ponytail: ignores per-query next_page_token (only set past 1000 vulns for one package version).
        out += [[v["id"] for v in (res.get("vulns") or []) if isinstance(v.get("id"), str)] for res in results]
    return out


async def osv_vuln(c: httpx.AsyncClient, vuln_id: str) -> dict[str, Any]:
    if not ID.fullmatch(vuln_id):  # IDs come from OSV responses; never let one shape the URL path
        raise SourceError("unexpected OSV ID format")
    r = await c.get(f"{OSV_API}/vulns/{vuln_id}")
    r.raise_for_status()
    return r.json()


async def kev_cves(c: httpx.AsyncClient) -> set[str]:
    r = await c.get(KEV_URL)
    r.raise_for_status()
    return {v["cveID"] for v in r.json().get("vulnerabilities") or [] if isinstance(v.get("cveID"), str)}


async def nvd_cvss(c: httpx.AsyncClient, cve: str) -> tuple[str | None, float | None]:
    r = await c.get(NVD_API, params={"cveId": cve})
    r.raise_for_status()
    for item in r.json().get("vulnerabilities") or []:
        metrics = (item.get("cve") or {}).get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            for m in metrics.get(key) or []:
                data = m.get("cvssData") or {}
                if data.get("vectorString"):
                    return data["vectorString"], data.get("baseScore")
    return None, None


def _ts(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def normalize_osv(v: dict[str, Any], ecosystem: str, package: str) -> dict[str, Any]:
    """OSV record -> security_advisories fields. vendor_facts is the published text, verbatim (truncated only)."""
    affected = [a for a in v.get("affected") or [] if isinstance(a, dict)]
    mine = [a for a in affected if (a.get("package") or {}).get("name") == package
            and (a.get("package") or {}).get("ecosystem") == ecosystem] or affected[:1]
    patched = sorted({e["fixed"] for a in mine for r in a.get("ranges") or [] for e in r.get("events") or []
                      if isinstance(e.get("fixed"), str)})
    word = (v.get("database_specific") or {}).get("severity")
    vector = next((s.get("score") for s in v.get("severity") or [] if str(s.get("type", "")).startswith("CVSS")), None)
    sev, known = severity_from_word(word) if word else ("medium", False)
    facts = "\n\n".join(x for x in (v.get("summary"), v.get("details")) if isinstance(x, str))
    refs = [r.get("url") for r in v.get("references") or [] if r.get("type") in ("ADVISORY", "WEB") and r.get("url")]
    return {
        "external_id": v["id"],
        "aliases": sorted({a for a in v.get("aliases") or [] if isinstance(a, str)})[:50],
        "title": str(v.get("summary") or v["id"])[:500],
        "url": (refs[0] if refs else f"https://osv.dev/vulnerability/{v['id']}")[:500],
        "ecosystem": ecosystem,
        "package": package,
        "affected_ranges": [{"package": a.get("package"), "ranges": a.get("ranges") or [],
                             "versions": (a.get("versions") or [])[:200]} for a in mine],
        "patched_versions": patched,
        "severity": sev if known else None,
        "cvss_vector": str(vector)[:255] if vector else None,
        "vendor_facts": facts[:MAX_FACTS] or str(v["id"]),
        "published_at": _ts(v.get("published")),
        "modified_at": _ts(v.get("modified")),
    }


def severity_from_nvd(score: float | None) -> str | None:
    sev, known = severity_from_cvss(score)
    return sev if known else None
