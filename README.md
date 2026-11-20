# trident — Open WebUI's Open Terminal, running as Agent Substrate actors

`trident` is a middleware server that takes Open WebUI's
[Open Terminal](https://github.com/open-webui/open-terminal) integration and
runs it on [Agent Substrate](https://github.com/agent-substrate/substrate):
instead of a bare-metal Open Terminal install, **each Open WebUI chat gets its
own substrate actor** — a gVisor-sandboxed, snapshot-suspendable micro-VM
holding the real Open Terminal server, the coding-agent CLIs, and the chat's
workspace.

```
Open WebUI ──Open Terminal protocol (HTTP+WS)──▷ trident
   Authorization: Bearer <key>      │  auth, chat→actor map (sqlite)
     X-User-Id / X-Session-Id       │  /api/config served locally; /templates → 404
                                    │  everything else: pass-through proxy
   gRPC ateapi ──actor create/resume/suspend/delete + egress policies
   CONNECT to atenet-router:8444 ──▷ Actor (gVisor, MEMORY snapshot)
                                      └ open-terminal :8000 + claude/codex CLIs
```

## How it works

- The data path never re-implements the protocol. Each actor runs the **real**
  `open-terminal` server (built into `images/actor`), so Open WebUI's agent
  discovery (`GET /agents`), agent turns (`POST /agents/{provider}/sessions` +
  the agent WS), terminal panel, file browser, git, and notebooks are proxied
  byte-for-byte.
- Trident satisfies the contract-critical endpoints itself: a public
  `GET /api/config` features map (no actor wake), a 404 (with JSON `detail`) on
  `GET /api/v1/terminals/templates` to stay in plain-terminal mode, and
  Bearer-key auth mirroring open-terminal's error body.
- Actors are named deterministically from `(X-User-Id, X-Session-Id)` —
  `ot-u<hash>-c<hash>` — and created on demand from the ActorTemplate with a
  per-actor egress policy (`tls_passthrough` for LLM APIs and package
  registries; deny-by-default otherwise).
- Lifecycle is trident-s job (substrate never auto-suspends): an idle ticker
  suspends actors after `TRI_IDLE_TTL` (default 10m) once no request or spliced
  WebSocket is live, and deletes them past `TRI_MAX_AGE`. MEMORY-fidelity
  snapshots preserve the agent process, so a resumed chat continues
  mid-conversation.
- The data plane always goes through atenet-router's **CONNECT tunnels
  (port 8444)**, whose route timeout is 0 — long agent WebSockets and file
  streams never hit envoy's 5-minute HTTP cap on the :443 ingress path.

## Quickstart (kind: substrate quickstart cluster)

```bash
# 0. A substrate cluster (the repo's quickstart on kind):
#    hack/create-kind-cluster.sh; ATE_INSTALL_KIND=true go run ./cmd/ate-setup deploy ate-system ...
# 1. Build the actor image and print its pinned digest:
OCI_REPO=ghcr.io/you/ot-actor scripts/build-actor-image.sh
# 2. Create atespace + ActorTemplate (waits for the golden snapshot):
trident bootstrap -image ghcr.io/you/ot-actor@sha256:...
# 3. Apply the worker pool, RBAC and the Trident Deployment:
cp manifest/values.sh.example manifest/values.sh  # edit values
scripts/deploy.sh
# 4. Or run trident out-of-cluster against the kind cluster:
TRI_BACKEND=substrate TRI_API_KEY=... TRI_LISTEN_ADDR=127.0.0.1:8080 bin/trident serve
```

For development **without a cluster** (M0 path):

```bash
docker buildx build -t ot-actor:dev images/actor
TRI_API_KEY=test-key \
TRI_BACKEND=docker TRI_DOCKER_IMAGE=ot-actor:dev \
TRI_LISTEN_ADDR=127.0.0.1:8080 bin/trident serve
```

## Open WebUI setup

Admin Settings → Integrations → Open Terminal:

- **URL**: trident-s URL (`http://...` as reachable from Open WebUI — a NodePort,
  ingress, or `kubectl port-forward svc/trident 8080:80`)
- **API key**: the value of `TRI_API_KEY`

Open WebUI probes `GET /api/v1/terminals/templates` (answered 404), reads the
features map, and shows the terminal in chat. Discovered agent models appear as
`claude-code/<model>`, `codex/<model>`; agent runs stream with tool approvals,
Stop (`DELETE` the session) and continuation (resume from the chat's snapshot).

## Configuration (env; flags override where noted)

| Var | Default | Meaning |
|---|---|---|
| `TRI_API_KEY` | (required) | front-side Bearer key Open WebUI presents |
| `TRI_ACTOR_API_KEY` | = `TRI_API_KEY` | keep equal — WS auth frames pass through unrewritten |
| `TRI_CONSOLE_TOKEN` | (required with egress flow) | human-only console token (≠ `TRI_API_KEY`); manages the approval UI |
| `TRI_CONSOLE_SHOW_DEFAULT` | `true` | prefill the default console token on console pages |
| `TRI_BACKEND` | `substrate` | `substrate` or `docker` (dev) |
| `TRI_STATE_DB` | `sessionmap.db` | sqlite chat→actor map + egress bookkeeping |
| `TRI_LISTEN_ADDR` | `127.0.0.1:8080` | facade address |
| `TRI_ATESPACE` | `ots-webui` | atespace for chat actors |
| `TRI_TEMPLATE_REF` | `ots-webui/open-terminal` | `"<atespace>/<name>"` ActorTemplate |
| `TRI_ACTOR_PREFIX` | `ot-` | actor-name prefix (reconcile + cleanup scope) |
| `TRI_ACTOR_PORT` | `8000` | the open-terminal port inside the actor |
| `TRI_IDLE_TTL` | `10m` | idle → suspend (snapshot, pod freed) |
| `TRI_DELETE_IDLE_TTL` | `48h` | idle → full purge (frees the durable volume) |
| `TRI_MAX_AGE` | `168h` | hard cap from creation |
| `TRI_SUSPEND_DURABILITY` | `async` | `async` (fast, node-local then background upload) or `sync` |
| `TRI_EGRESS_HOSTS` | anthropic/openai/pypi/npm… | per-actor tls-passthrough allowlist |
| `TRI_FEATURES_JSON` | core on, browser/desktop off | the `/api/config` features map |
| `TRI_DOCKER_IMAGE` | — | required for `TRI_BACKEND=docker` |
| `TRI_DOCKER_ENV` | — | extra `K=V` env for docker-mode actors |
| `TRI_API_SERVICE`, `TRI_CLIENT_SA`, `TRI_ROUTE_NAMESPACE`, `TRI_ROUTE_SA` | api / ate-client / ate-system / atenet-client | substrate connection details |
| `ATE_NAMESPACE`, `TRI_API_TOKEN_FILE`, `KUBECONFIG` | ate-system / — / — | ateapi namespace, token file, out-of-cluster kubeconfig |
| `TRI_LOG_LEVEL` | info | `debug` for request logging |
| `TRI_TLS_LISTEN_ADDR` | `:8443` | egress-callback TLS listener |
| `TRI_EGRESS_CALLBACK` | — | in-cluster callback Service:port (enables the approval flow) |
| `TRI_EGRESS_OBSERVER` / `..._POD_SELECTOR` | `true` / `app=atenet-egress` | gateway-deny-log observer |
| `TRI_CPU_MILLICORES` / `TRI_MEMORY_BYTES` | 1000 / 2 Gi | ActorTemplate sizing at bootstrap (workers must fit restore margin: 2 CPU / 4608Mi, see manifest/values.sh.example; a 2560Mi worker makes resume fail with "no worker has room") |

The complete, current reference lives in **`scripts/trident.env.example`** (usable
with `--env-file`). Pre-rename `OTS_*` variables still work as fallbacks where
`TRI_*` names are unset. The deployed instance's env can be kept in a file such
as `/home/vsupe/.ot-trident.env` (docker `--env-file`-compatible).

Substrate layout: `manifest/actor` → embedded ActorTemplate,
`manifest/workers/workerpool.yaml.tmpl` → WorkerPool CRD,
`manifest/trident/` → Deployment + RBAC.

## Caveats (known, deliberate)

- **Key:** the shim key and the actor key are the same value by design. Setting
  `TRI_ACTOR_API_KEY` to something else breaks agent/terminal WebSockets in v1
  (their auth arrives in the first WS frame, not a header) and is logged as a
  startup warning.
- **Upgrades:** actor images are digest-pinned; a new template cold-boots every
  chat actor and drops in-memory agent sessions (files persist in the durable
  `/home/user` volume). Deploy in a maintenance window.
- **Worker loss** (node gone, worker OOM) drops in-memory agent sessions; Open
  WebUI surfaces its reconnect flow and the turn can be retried.
- **Unsaved chats** (no `X-Session-Id`) share the user's per-user "adhoc"
  actor; chats get their own actor on first save (Open WebUI saves on first
  message by default, so this rarely matters).
- **gVisor** compatibility of the agent toolchain (setcap python copy, `sudo`,
  `/proc` port detection) is the top validation item against a real substrate
  install; `TRI_BACKEND=docker` stays available as a fallback/demo mode.
- Browser/desktop features are feature-flagged off in v1; the flags are how
  you'd re-enable them after validating Chromium/XFCE under the sandbox.

## Repository map

```
cmd/trident/            serve | bootstrap | version
internal/facade/        frontend: auth, /api/config, /templates 404, per-actor reverse proxy
internal/pool/          chat→actor map, singleflight, idle/max-age ticker, WS refcounts
internal/backend/       Backend interface
internal/backend/substrate/   ate gRPC client, podidentity certs, CONNECT dialer, lifecycle
internal/backend/fakedocker/  local docker dev backend
internal/sessionmap/    sqlite persistence
internal/model/         RouteKey identity + actor naming
third_party/ateapi/     generated ateapi gRPC stubs (copied from substrate, Apache-2.0)
third_party/_reference-sources/  build-ignored copies the adapted code is drawn from
images/actor/           open-terminal + agent CLIs actor image
manifest/               deploy templates (actor template, worker pool, shim, RBAC, values)
scripts/                build/deploy/e2e helpers
```

## Verification

```bash
go test ./test/          # facade, pool, sessionmap, routekey unit tests
test/e2e/local_e2e_test.go   # full protocol surface against a docker actor
scripts/e2e-kind.sh      # end-to-end against a kind substrate install
```

Manual Open WebUI checklist: connect server → models appear → chat turn with
claude-code streams and approvals → Stop → continue → terminal panel + upload →
second concurrent chat gets its own actor → idle pod freed → reopen chat resumes
mid-conversation.

## License

Apache-2.0. Adapted components from agent-substrate/substrate keep their
license headers; see `third_party/ateapi/NOTICE`.
