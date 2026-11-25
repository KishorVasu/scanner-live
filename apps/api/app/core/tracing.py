"""OpenTelemetry tracing to Tempo (Phase 6, OQ-8). Off unless OTEL_EXPORTER_OTLP_ENDPOINT is set.

Spans can carry exception messages and URLs, so every attribute and event passes the redactor before export (rule 4),
the same as log records. No request or response bodies or headers are captured (the instrumentations' defaults).
"""

import os
from collections.abc import Sequence

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import Event, ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult

from app.core.redaction import get_redactor

_done = False


def _clean(attrs):
    if not attrs:
        return attrs
    r = get_redactor()
    return {k: r.redact(v) if isinstance(v, str) else v for k, v in attrs.items()}


class RedactingExporter(SpanExporter):
    def __init__(self, inner: SpanExporter) -> None:
        self.inner = inner

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        return self.inner.export([
            ReadableSpan(
                name=s.name, context=s.context, parent=s.parent, resource=s.resource, attributes=_clean(s.attributes),
                events=[Event(e.name, _clean(e.attributes), e.timestamp) for e in s.events], links=s.links,
                kind=s.kind, status=s.status, start_time=s.start_time, end_time=s.end_time,
                instrumentation_scope=s.instrumentation_scope,
            )
            for s in spans
        ])

    def shutdown(self) -> None:
        self.inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self.inner.force_flush(timeout_millis)


def setup_tracing(app=None, celery: bool = False, exporter: SpanExporter | None = None) -> bool:
    """Install the tracer provider once per process and instrument FastAPI or Celery. Returns True when active."""
    global _done
    if exporter is None:
        if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
            return False
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        exporter = OTLPSpanExporter()
    if not _done:
        service = os.environ.get("OTEL_SERVICE_NAME", "sp-worker" if celery else "sp-api")
        provider = TracerProvider(resource=Resource.create({"service.name": service}))
        provider.add_span_processor(BatchSpanProcessor(RedactingExporter(exporter)))
        trace.set_tracer_provider(provider)
        _done = True
    if app is not None:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app, excluded_urls="api/health,metrics")
    if celery:
        from opentelemetry.instrumentation.celery import CeleryInstrumentor

        CeleryInstrumentor().instrument()
    return True
