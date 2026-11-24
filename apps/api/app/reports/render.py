"""Report -> HTML -> PDF (WeasyPrint). HTML is built only from escaped values; WeasyPrint may fetch nothing."""

from html import escape

from app.db.intel import Report

CSS = """
@page { size: A4; margin: 18mm 16mm; @bottom-right { content: counter(page) " / " counter(pages); font-size: 8pt; } }
body { font-family: "DejaVu Sans", sans-serif; font-size: 9.5pt; color: #1f2933; }
h1 { font-size: 16pt; margin: 0 0 4pt; } h2 { font-size: 12pt; margin: 14pt 0 4pt; } h3 { font-size: 10.5pt; }
table { width: 100%; border-collapse: collapse; margin: 4pt 0 8pt; }
th, td { border: 0.5pt solid #cbd2d9; padding: 2.5pt 4pt; text-align: left; vertical-align: top; }
th { background: #f0f4f8; } .note { background: #fffbea; border: 0.5pt solid #f0b429; padding: 5pt; }
.ai { border-left: 2pt solid #1d4ed8; padding-left: 6pt; } .status { font-weight: bold; text-transform: uppercase; }
"""


def _t(rows: list[dict], cols: list[tuple[str, str]]) -> str:
    if not rows:
        return "<p>None.</p>"
    head = "".join(f"<th>{escape(h)}</th>" for _, h in cols)
    body = "".join("<tr>" + "".join(f"<td>{escape(str(r.get(k) if r.get(k) is not None else ''))}</td>"
                                    for k, _ in cols) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def html(report: Report) -> str:
    c = report.content
    parts = [f"<h1>{escape(report.title)}</h1>",
             f"<p class='status'>{escape(report.status.value)}</p>",
             f"<p>Generated {escape(c['generated_at'])}. Scope: {escape(c['scope'])}.</p>",
             f"<p class='note'>{escape(c['statement'])}</p>",
             "<h2>Not scanned</h2>",
             ("<ul>" + "".join(f"<li>{escape(n)}</li>" for n in c["not_scanned"]) + "</ul>")
             if c["not_scanned"] else "<p>Every listed repository has at least one successful scan.</p>"]
    if report.narrative:
        parts += ["<h2>Summary (AI-written draft, reviewed by an approver)</h2>",
                  f"<div class='ai'>{''.join(f'<p>{escape(x)}</p>' for x in report.narrative.split(chr(10)) if x.strip())}</div>"]
    elif report.narrative_note:
        parts.append(f"<p><em>{escape(report.narrative_note)}</em></p>")
    for p in c["projects"]:
        sev = ", ".join(f"{k}: {v}" for k, v in p["open_findings_by_severity"].items()) or "none recorded by scans"
        parts += [f"<h2>{escape(p['project'])}</h2>",
                  f"<p>Criticality: {escape(p['criticality'])}. Open findings: {escape(sev)}. "
                  f"Integrity events (30 days): {p['integrity_events_30d']}.</p>",
                  "<h3>Repositories</h3>",
                  _t([{**r, "scans": ", ".join(f"{k} {v}" for k, v in r["last_successful_scan"].items()) or "not scanned"}
                      for r in p["repositories"]], [("repository", "Repository"), ("inventory", "Inventory"),
                                                    ("scans", "Last successful scans")]),
                  "<h3>Top open findings</h3>",
                  _t(p["top_findings"], [("severity", "Severity"), ("title", "Title"), ("location", "Where"),
                                         ("rule_id", "Rule"), ("scanner", "Scanner"), ("status", "Status")]),
                  "<h3>Advisory impacts</h3>",
                  _t([{**i, "kev": "yes" if i["known_exploited"] else "", "fixed": ", ".join(i["fixed_in"] or [])}
                      for i in p["advisory_impacts"]],
                     [("classification", "Impact"), ("advisory", "Advisory"), ("package", "Package"),
                      ("kev", "Known exploited"), ("fixed", "Fixed in"), ("title", "Title")])]
    return f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{''.join(parts)}</body></html>"


def _no_fetch(url: str, *args, **kwargs):
    raise ValueError(f"report rendering fetches nothing ({url[:40]})")


def pdf(report: Report) -> bytes:
    from weasyprint import HTML  # imported lazily: needs Pango system libraries (present in the API image and CI)

    return HTML(string=html(report), url_fetcher=_no_fetch).write_pdf()
