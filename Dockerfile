# =============================================================================
# Tailscale JIT Access Management: Docker Image
# =============================================================================
# Build:  docker build -t tailscale-jit-access .
# Run:    docker run -d --name jit-access --env-file .env -v jit-data:/app/data \
#           -p 127.0.0.1:5000:5000 tailscale-jit-access
#
# NOTE: Tailscale Serve must run on the HOST (not in the container).
#       Always bind the host port to 127.0.0.1 (-p 127.0.0.1:5000:5000) so the
#       app is only reachable via Tailscale Serve. Omitting 127.0.0.1 exposes
#       port 5000 on all interfaces with no authentication.
# =============================================================================

FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Runtime stage ---
FROM python:3.12-slim

# Security: run as non-root
RUN groupadd -r jitaccess && useradd -r -g jitaccess -d /app -s /sbin/nologin jitaccess

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application
COPY app.py .
COPY templates/ templates/

# Create data directory for SQLite DB
RUN mkdir -p /app/data && chown -R jitaccess:jitaccess /app

# Default DB path inside data volume
ENV DB_PATH=/app/data/jit_access.db

USER jitaccess

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/healthz')" || exit 1

# Run with gunicorn + eventlet for production WebSocket support
CMD ["gunicorn", \
     "--worker-class", "eventlet", \
     "--workers", "1", \
     "--bind", "127.0.0.1:5000", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "app:app"]
