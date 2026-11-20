# Trident middleware (the shim itself): Open WebUI's Open Terminal protocol
# front for Agent Substrate actors. The binary is compiled on the build host
# (same linux/amd64) and copied in — no Go toolchain layer needed.
#
# Runtime needs (mount or pass at `docker run`):
#   --env-file trident.env          the TRI_* configuration
#   -v <kubeconfig>:/kube/config:ro + -e KUBECONFIG=/kube/config   (out-of-cluster)
#   -v <state dir>:/var/lib/trident  (sqlite session/egress store)
#   -p 8080:8080 -p 8443:8443       facade + egress-callback TLS
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -m -d /var/lib/trident trident
COPY trident /usr/local/bin/trident
USER trident
ENV TRI_STATE_DB=/var/lib/trident/sessionmap.db
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/trident"]
CMD ["serve"]
