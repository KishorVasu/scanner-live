"""Phase 6 observability: metric labels stay bounded, traces never carry secret values (rule 4)."""

import uuid

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from app.core.tracing import RedactingExporter
from tests.conftest import login
from tests.test_redaction import FAKES


async def test_http_metrics_use_route_templates_not_raw_paths(client, make_user):
    await login(client, await make_user("viewer"))
    fid = uuid.uuid4()
    assert (await client.get(f"/api/findings/{fid}")).status_code == 404
    await client.get("/api/no-such-route-" + uuid.uuid4().hex)
    text = (await client.get("/metrics/")).text
    assert 'route="/api/findings/{finding_id}"' in text and 'status="404"' in text
    assert str(fid) not in text and "no-such-route" not in text and 'route="unmatched"' in text


def test_spans_are_redacted_before_export():
    inner = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(RedactingExporter(inner)))
    secret = FAKES["github-token"]
    with provider.get_tracer("t").start_as_current_span("s") as span:
        span.set_attribute("http.url", f"/api/x?token={secret}")
        span.record_exception(RuntimeError(f"failed with {secret}"))
    (out,) = inner.get_finished_spans()
    assert secret not in str(dict(out.attributes)) + str([dict(e.attributes) for e in out.events])
    assert out.events[0].name == "exception"
