# ot-shim actor image: the real open-terminal server plus coding-agent CLIs,
# sized for substrate actors (HTTP on port 8000, wakeup probe /health).
# This is a slim variant of upstream's Dockerfile + agents stage: no browser,
# desktop, docker CLI or office tooling (feature-disabled in the template).
#
# Build: scripts/build-actor-image.sh (pushes and prints the digest-pinned ref
# substrate templates require).

# Pinned to a specific patch version for reproducible builds.
FROM python:3.12.16-slim AS ot-src
ARG OT_REF=v0.17.20
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 --branch ${OT_REF} https://github.com/open-webui/open-terminal /src/open-terminal

FROM python:3.12.16-slim

ARG OT_REF
LABEL org.opencontainers.image.title="ot-shim open-terminal actor"
LABEL org.opencontainers.image.source="https://github.com/open-webui/open-terminal"
LABEL org.opencontainers.image.description="Open Terminal server + claude-code/codex CLIs for substrate actors (open-terminal ${OT_REF})"

RUN apt-get update && apt-get install -y --no-install-recommends \
    coreutils findutils grep sed gawk diffutils patch \
    less file tree bc man-db \
    curl wget net-tools iputils-ping dnsutils netcat-openbsd socat telnet \
    openssh-client rsync \
    vim nano \
    git gh \
    build-essential \
    jq xmlstarlet sqlite3 \
    ffmpeg \
    zip unzip tar gzip bzip2 xz-utils zstd p7zip-full \
    procps htop lsof strace sysstat \
    sudo tmux screen tini \
    ca-certificates gnupg apt-transport-https \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Node.js (LTS)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# DNS-failure reporter preload: any dynamically-linked process that fails a
# name lookup (curl, the agents' node CLIs, python) appends the host to a
# local report file the shim sweeps over /execute. libotpreload.so is
# compiled on the build host (same linux/amd64) and copied in.
COPY libotpreload.so /usr/local/lib/libotpreload.so
ENV LD_PRELOAD=/usr/local/lib/libotpreload.so
# The report file dir also exists at image level for cold boots.
RUN mkdir -p /tmp/.ot-egress

# Build the server from the pinned source and give the server process a
# capability-bearing python copy, mirroring upstream: the system python3 stays
# clean so user-spawned processes remain "dumpable" for port detection.
COPY --from=ot-src /src/open-terminal /src/open-terminal
RUN pip install --no-cache-dir /src/open-terminal \
    && cp "$(readlink -f "$(which python3)")" /usr/local/bin/python3-ot \
    && setcap cap_setgid+ep /usr/local/bin/python3-ot \
    && sed -i "1s|.*|#!/usr/local/bin/python3-ot|" "$(which open-terminal)"

RUN useradd -m -s /bin/bash user && echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Coding agents, installed globally (outside home) so durable volume mounts
# and snapshots share the binaries while keeping their own credentials.
RUN npm install --global --prefix /usr/local --include=optional \
    @openai/codex@latest \
    @anthropic-ai/claude-code@latest \
    && npm cache clean --force
ENV DISABLE_AUTOUPDATER=1

USER user
ENV SHELL=/bin/bash
ENV PATH="/home/user/.local/bin:${PATH}"
WORKDIR /home/user

# The substrate actor contract: a plain HTTP server on this port (the shim's
# CONNECT tunnels dial it; the template's wakeup probe checks /health).
EXPOSE 8000

# tini takes PID 1 so agent subprocesses get proper signal handling.
ENTRYPOINT ["/usr/bin/tini", "--", "open-terminal", "run", "--host", "0.0.0.0", "--port", "8000"]
