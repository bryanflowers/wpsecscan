# WPSecScan — defensive WordPress security scanner
# Multi-stage build: install + run from a slim runtime image.

FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
# Copy installed packages from the builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy app
COPY wpsecscan ./wpsecscan
COPY run.py ./run.py
COPY scripts ./scripts

# Default volume for reports + state — bind-mount this from the host:
#   docker run -v $(pwd)/reports:/reports wpsecscan https://target.com --out /reports
VOLUME ["/reports", "/root/.wpsecscan"]

# Run the CLI by default; user can override with `docker run wpsecscan --shell` etc.
ENTRYPOINT ["python", "-m", "wpsecscan"]
CMD ["--help"]

LABEL org.opencontainers.image.title="WPSecScan"
LABEL org.opencontainers.image.description="Defensive WordPress security scanner (use on sites you own)"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
LABEL org.opencontainers.image.source="https://github.com/bryanflowers/wpsecscan"
LABEL org.opencontainers.image.version="2.2.0"
