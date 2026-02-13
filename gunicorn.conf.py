"""Gunicorn configuration for Tailscale JIT Access Management."""

# Bind to localhost only: Tailscale Serve handles external access
bind = "127.0.0.1:5000"

# Use eventlet for WebSocket (Flask-SocketIO) support
worker_class = "eventlet"

# Single worker: SQLite doesn't handle concurrent writers well
workers = 1

# Timeout for long-running requests (Tailscale API calls)
timeout = 120

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Graceful shutdown
graceful_timeout = 30
