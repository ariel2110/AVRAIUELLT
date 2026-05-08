# =============================================================================
# Vault Bridge — Multi-stage Dockerfile
#
# Stage 1 (builder): Installs Python dependencies into an isolated /install
#   prefix so we can copy just the packages (no build toolchain) into the
#   final image.
#
# Stage 2 (runtime): Minimal python:3.12-slim image. Copies installed
#   packages from builder. Runs as non-root user 'vault' (uid 1001).
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: builder — install dependencies only
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install C build dependencies required by asyncpg and some other packages.
# These stay in the builder stage and never reach the final image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker layer caching.
# Re-installing deps only happens when requirements.txt changes.
COPY requirements.txt .

# Install all packages under /install so we can COPY the tree to the
# runtime stage without bringing along pip, setuptools, or build tools.
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: runtime — lean production image
# -----------------------------------------------------------------------------
FROM python:3.12-slim

# Security: disable .pyc files and ensure stdout/stderr are unbuffered
# so logs appear immediately in `docker logs`.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy only the installed packages from the builder stage.
# This keeps the final image free of gcc, libpq headers, etc.
COPY --from=builder /install /usr/local

# Copy application source code.
COPY main.py .

# Create a non-root user to run the application.
# uid/gid 1001 avoids collision with common system users.
RUN groupadd --gid 1001 vault \
    && useradd --uid 1001 --gid vault --no-create-home --shell /bin/false vault \
    && chown -R vault:vault /app

USER vault

# Expose the internal port. The docker-compose port binding restricts external
# access to the Hostinger private VPC IP — this EXPOSE is documentation only.
EXPOSE 8000

# --workers 2: two Uvicorn worker processes to handle concurrent requests.
# --no-access-log: access logging is handled by our structured middleware
#   instead, which masks the secret key header value.
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--no-access-log"]
