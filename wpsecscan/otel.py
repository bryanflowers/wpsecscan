"""L31 OpenTelemetry traces (opt-in).

When the `opentelemetry-api` + `opentelemetry-sdk` + `opentelemetry-exporter-otlp`
packages are installed AND `WPSECSCAN_OTLP_ENDPOINT` is set, every scan emits
one root span per scan + one child span per check.

Set the endpoint to e.g. `http://localhost:4318` for a local Jaeger /
Honeycomb / Tempo agent. No-op otherwise — no exceptions, no log spam.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any


_tracer = None
_initialized = False


def _try_init() -> None:
    """Initialise the OTel tracer once per process. Safe to call repeatedly.

    B8: the `_initialized` flag is set ONLY after a definitive outcome — either
    success, missing dep, or hard failure. That way a transient env change
    (e.g. WPSECSCAN_OTLP_ENDPOINT being unset on first call and set later)
    re-attempts initialisation rather than being permanently no-op.
    """
    global _tracer, _initialized
    if _initialized:
        return
    endpoint = os.environ.get("WPSECSCAN_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        # No endpoint: leave _initialized=False so a later env change re-tries.
        return
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        resource = Resource.create({"service.name": "wpsecscan"})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces")
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("wpsecscan")
        _initialized = True
    except ImportError:
        # OpenTelemetry packages not installed — cache the negative result so
        # we don't re-attempt the imports on every span() call.
        _initialized = True
    except Exception:  # noqa: BLE001
        # Misconfiguration — cache the negative result, don't crash the scan.
        _initialized = True


def is_enabled() -> bool:
    _try_init()
    return _tracer is not None


@contextmanager
def span(name: str, **attributes: Any):
    """Context manager that opens a span if OTel is enabled, else a no-op."""
    _try_init()
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as sp:
        for k, v in attributes.items():
            try:
                sp.set_attribute(k, v)
            except Exception:  # noqa: BLE001
                pass
        yield sp


def add_attributes(sp, **attributes: Any) -> None:
    """Late-set attributes on a span (e.g. duration, finding count)."""
    if sp is None:
        return
    for k, v in attributes.items():
        try:
            sp.set_attribute(k, v)
        except Exception:  # noqa: BLE001
            pass
