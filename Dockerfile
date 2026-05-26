# Item #64 — reproducible Docker image for wpsecscan.
#
# Build:    docker build -t wpsecscan .
# Run:      docker run --rm wpsecscan https://example.com --json-only
# Output:   docker run --rm -v "$PWD/reports:/out" wpsecscan https://example.com --out /out
#
# Built on python:3.12-slim. Pinned to a specific minor so reproducible
# builds stay reproducible. Update the pin when CI bumps the matrix.

FROM python:3.12-slim AS base

# OS-level deps:
#   - openssl + bind9-dnsutils for tls_modern (#21/22) + dns_security
#   - tini: PID-1 reaper so docker stop / Ctrl-C terminates the scan cleanly
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openssl bind9-dnsutils tini ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Run as a non-root user so a `docker run --user 10001` deploy works without
# additional CAP drops. UID is fixed so volume permissions are predictable.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin wpsec
WORKDIR /home/wpsec

COPY --chown=wpsec:wpsec pyproject.toml ./
COPY --chown=wpsec:wpsec wpsecscan ./wpsecscan
COPY --chown=wpsec:wpsec scripts ./scripts
COPY --chown=wpsec:wpsec run.py ./run.py

# Install wpsecscan + its declared deps from pyproject. Pull in the
# optional extras most users will want: dnspython (MX + DNSSEC),
# python-docx (Word reports), reportlab (true PDF), pillow (PNG charts).
RUN pip install --no-cache-dir . \
 && pip install --no-cache-dir dnspython python-docx reportlab pillow

USER wpsec
ENV WPSECSCAN_HOME=/home/wpsec/.wpsecscan
RUN mkdir -p ${WPSECSCAN_HOME}/reports

# Bind-mount points for results + state.
VOLUME ["/out", "/home/wpsec/.wpsecscan"]

ENTRYPOINT ["/usr/bin/tini", "--", "wpsecscan"]
CMD ["--help"]

LABEL org.opencontainers.image.title="wpsecscan"
LABEL org.opencontainers.image.description="Defensive WordPress security scanner. Authorized testing only."
LABEL org.opencontainers.image.source="https://github.com/bryanflowers/wpsecscan"
LABEL org.opencontainers.image.licenses="MIT"
