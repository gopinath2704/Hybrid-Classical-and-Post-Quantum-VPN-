# Shared Dockerfile for PQVPN server and development client roles.
# Usage: docker compose up --build
#
# Runs only the VPN server daemon (control listener + AES-256-GCM UDP tunnel).
# The optional management API is a separate, loopback-bound process.
#
# Requires:
#   - NET_ADMIN capability (for TUN interface allocation)
#   - /dev/net/tun device mapped in from the host
#
FROM ubuntu:24.04

# ─── Environment ─────────────────────────────────────────────────────────────
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ─── System dependencies ──────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    git \
    nftables \
    cmake \
    gcc \
    g++ \
    ninja-build \
    libssl-dev \
    net-tools \
    iproute2 \
    iptables \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ─── Native and Python dependencies ──────────────────────────────────────────
COPY scripts/install-liboqs.sh /tmp/install-liboqs.sh
RUN bash /tmp/install-liboqs.sh /usr/local
COPY . .
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -c constraints-tested.txt .

# ─── Ports ───────────────────────────────────────────────────────────────────
# 51820 — KEMTLS handshake TCP port + AES-256-GCM UDP tunnel port
EXPOSE 51820 51820/udp

# Compose overrides this command for the development client role.
CMD ["python3", "-m", "vpn.cli", "server", "--config", "/etc/pqvpn/server.toml"]
