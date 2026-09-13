# tsportmap

tsportmap is a single containerised Go binary that embeds one Tailscale node
(via `tsnet`, in userspace — no `/dev/net/tun`, no `NET_ADMIN`) and relays
**declared port mappings in both directions**: `out` mappings listen on the
container's own network and dial onward to a tailnet peer, `in` mappings listen
on the tailnet and dial onward to a target reachable from the container. What it
is *not*: it is not a proxy in the general sense. There is no SOCKS5, no HTTP
CONNECT, no ad-hoc destination selection and no dynamic configuration API. A
caller can only ever reach a destination that an operator wrote into an
environment variable before the process started. That restriction is the
product, not a missing feature — it is what makes the reachable set of a
tsportmap node auditable by reading its configuration.

MIT licensed. `tailscale.com` is the only third-party dependency; everything
else is the standard library.

---

## Do you actually need this?

Probably not. Several mature things overlap with tsportmap, and most of the time
one of them is the better answer. In rough order of how often it applies:

- **You only need to expose HTTP or HTTPS services on your tailnet.** Use
  [tsnsrv](https://github.com/boinkor-net/tsnsrv) or
  [tsbridge](https://github.com/jtdowney/tsbridge). Both put an HTTP reverse
  proxy behind a tsnet node, both handle Tailscale certificates and per-service
  nodes, and both are more mature at that job than this is. If your traffic is
  requests and responses over HTTP, stop here.

- **You are on Kubernetes.** The official
  [Tailscale Kubernetes operator](https://tailscale.com/kb/1236/kubernetes-operator)
  already does this. Its `ProxyGroup` egress path implements per-port mappings
  with explicit `matchPort`/`targetPort`, it is supported software with an
  upgrade path, and it integrates with Services and Ingress rather than sitting
  beside them. tsportmap will run on Kubernetes, but choosing it there means
  choosing an unsupported thing over a supported one for no structural reason.

- **Your clients can speak SOCKS5.** Run the official `tailscale/tailscale`
  container with `TS_SOCKS5_SERVER` and point the client at it. It is one
  environment variable and it reaches your whole tailnet without anything being
  declared in advance. Note that the built-in SOCKS5 server is
  **unauthenticated**: bind it to loopback (`TS_SOCKS5_SERVER=localhost:1055`)
  and never to an address a neighbouring workload can reach.

tsportmap earns its place in one specific corner: you need **raw TCP or UDP**
port maps, **in either direction**, on a platform that **is not Kubernetes**,
where the client **cannot be made proxy-aware**. The archetype is a database
driver that opens a bare socket to `host:5432` and has no proxy setting — no
`ALL_PROXY`, no SOCKS support in the connection string, no way to wrap it. For
that case you need something that answers on a real local port and forwards, and
you would like the set of destinations it can reach to be a short list you can
read.

---

## Quick start (Docker)

There is no published image yet; build it.

```sh
git clone https://github.com/hakaitech/tsportmap
cd tsportmap
docker build -t tsportmap:dev .
```

Check a configuration before it touches the network. `--validate` runs the exact
parser that startup runs and prints what would be exposed:

```sh
docker run --rm \
  -e TSPM_OUT_POSTGRES='tcp,0.0.0.0:5432,db-1:5432,allow=172.17.0.0/16' \
  tsportmap:dev --validate
```

Then run it. The mapping below binds `0.0.0.0` **inside** the container and is
published only to the host's loopback, so nothing outside the machine can reach
it:

```sh
docker volume create tsportmap-state

docker run -d --name tsportmap \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -v tsportmap-state:/var/lib/tsportmap \
  -p 127.0.0.1:5432:5432 \
  -e TSPM_HOSTNAME=tsportmap \
  -e TSPM_TAGS=tag:proxy \
  -e TSPM_AUTHKEY='tskey-auth-...' \
  -e TSPM_OUT_POSTGRES='tcp,0.0.0.0:5432,db-1:5432,idle=30m' \
  tsportmap:dev
```

`psql -h 127.0.0.1 -p 5432` now reaches the tailnet host `db-1`. Nothing else on
your tailnet is reachable through this container.

Ready-made deployments live in [`deploy/`](deploy): a Compose file that runs
egress and ingress at once with the auth key supplied as a Docker secret, and a
Render Blueprint.

The status endpoints are served on `TSPM_METRICS_ADDR` (loopback by default,
because they are unauthenticated):

| Path       | Meaning |
| ---------- | ------- |
| `/healthz` | Liveness. Process-local only — it never consults the tailnet, so a peer outage cannot cause a restart loop. |
| `/readyz`  | Readiness. Every listener is bound *and* the node reports Running. Drops to 503 first during a drain. |
| `/metrics` | Prometheus text exposition. |

Metrics exported: `tsportmap_build_info`, `tsportmap_sessions_opened_total`,
`tsportmap_sessions_closed_total`, `tsportmap_sessions_active`,
`tsportmap_bytes_total` (labelled `direction="up"|"down"`),
`tsportmap_dial_failures_total`, `tsportmap_rejected_total` and
`tsportmap_session_duration_seconds`. All are labelled by `mapping`; the failure
and rejection counters carry a `reason` from a closed set — `allow_list`,
`dial_timeout`, `not_tailnet`, `refused`, `session_cap`, `other` — so a novel
error string from the network stack cannot mint a new time series per
connection.

Flags: `--validate` and `--version`. Everything else is environment.

---

## Configuration

Configuration is environment-only. Every problem is a startup error, never a
warning: a mapping whose allow-list was silently dropped is worse than a process
that refuses to start, because nothing downstream can distinguish "no
allow-list" from "the allow-list I wrote was ignored". An unset variable and one
set to the empty string mean the same thing — the default — because platform
dashboards routinely leave declared variables blank.

### Scalars

| Variable | Default | Notes |
| --- | --- | --- |
| `TSPM_HOSTNAME` | `tsportmap` | The node's name in the tailnet and in MagicDNS. |
| `TSPM_AUTHKEY` | *(none)* | Auth key or OAuth client secret. A `file:/path` prefix reads the value from that path instead, keeping it out of `/proc/<pid>/environ` and platform dashboards. Trailing whitespace is trimmed. Never logged, not even a prefix or a length. |
| `TS_AUTHKEY` | *(none)* | Fallback consulted only when `TSPM_AUTHKEY` is unset, so a container already configured for Tailscale needs no second variable. |
| `TSPM_TAGS` | *(none)* | Comma-separated, e.g. `tag:proxy`. Each entry must start with `tag:`. **Required** when `TSPM_AUTHKEY` holds an OAuth client secret (`tskey-client-…`). |
| `TSPM_STATE_DIR` | `/var/lib/tsportmap` | Where the node identity lives. Always set — never empty. |
| `TSPM_EPHEMERAL` | `false` | Register a node that control reaps on disconnect. |
| `TSPM_CONTROL_URL` | *(empty)* | Empty means Tailscale's coordination server. Set this for Headscale. |
| `TSPM_ACCEPT_ROUTES` | `false` | Use subnet routes advertised by other nodes. Off by default because it materially widens what the proxy can reach. |
| `TSPM_REQUIRE_TAILNET_DEST` | **`true`** | The destination guard. See [below](#why-the-destination-guard-exists). |
| `TSPM_METRICS_ADDR` | `127.0.0.1:9090` | Serves `/healthz`, `/readyz`, `/metrics`. Unauthenticated. |
| `TSPM_DIAL_TIMEOUT` | `10s` | Bounds one onward dial. Go duration syntax. |
| `TSPM_UP_TIMEOUT` | `90s` | Bounds waiting for the node to reach Running. |
| `TSPM_SHUTDOWN_GRACE` | `25s` | Bounds draining on SIGTERM. |
| `TSPM_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |

Booleans accept anything Go's `strconv.ParseBool` accepts (`true`/`false`,
`1`/`0`, `t`/`f`, and their cased spellings). Durations require a unit: `250ms`,
`30s`, `1m30s`.

### Mapping grammar

```
TSPM_OUT_<NAME> = <proto>,<listen>,<target>[,<key>=<value>]...
TSPM_IN_<NAME>  = <proto>,<listen>,<target>[,<key>=<value>]...
```

Mappings are found by scanning the environment for those two prefixes. There is
no index and no count variable: you add a relay by adding one variable and
remove it by deleting that variable, with nothing else to keep in sync. At least
one mapping is required.

| Field | Rules |
| --- | --- |
| `<NAME>` | The part after the prefix. Labels logs and the `mapping` metric label. Must be unique across `TSPM_OUT_*` and `TSPM_IN_*`, compared case-insensitively. |
| `proto` | `tcp` or `udp`. |
| `listen` | `host:port`; bracket IPv6 (`[::1]:8080`). **The host is required on `out`** — there is deliberately no default, because the correct bind address is a property of the platform and a wrong guess is either an unreachable listener or an open relay. On `in`, an omitted host (`:443`) means the node's own tailnet addresses. |
| `target` | `host:port`. The host is required. On `out`, prefer a MagicDNS short name over an FQDN: short names survive a tailnet rename. |

Options, comma-separated after the target:

| Option | Meaning |
| --- | --- |
| `tls=true` | Terminate TLS with the node's own Tailscale certificate. Valid **only** on `in` + `tcp`; rejected anywhere else. Requires MagicDNS and HTTPS certificates enabled on the tailnet. |
| `allow=CIDR\|CIDR\|…` | Pipe-separated prefixes restricting the source address of an accepted connection. Meaningful chiefly on `out`, where the sources are workloads on your platform's private network; on `in` the sources are tailnet addresses and ACL grants are the better instrument. Omitting it allows any source that can reach the bind address. Single addresses are written `/32` or `/128`. |
| `idle=<duration>` | Close a session that has moved no bytes in either direction for this long. On TCP, `0` (the default) means never reap. On UDP the default is `60s`, because UDP has no close handshake and an unbounded session table grows forever. |

An unknown option key is a startup error rather than a silently ignored field.
So is a duplicated option, an empty option field, and two mappings that would
claim the same listening socket — including the case where one is a wildcard
bind (`:8080`, `0.0.0.0:8080`) that covers the address another mapping named
explicitly.

### Worked examples

**Egress TCP with a port remap.** Local clients connect to port `5432` on the
container; the far side is a tailnet host that happens to serve Postgres on a
non-standard port. The listen port and the target port are independent.

```sh
TSPM_OUT_POSTGRES='tcp,0.0.0.0:5432,db-1:15432,idle=30m'
```

**Egress with an allow-list.** Same idea, but only workloads inside one subnet
of the platform's private network may use the mapping. Anything else is refused
before any dial happens and is counted under `reason="allow_list"`.

```sh
TSPM_OUT_REDIS='tcp,0.0.0.0:6379,cache-1:6379,allow=10.1.0.0/16|10.2.4.7/32,idle=10m'
```

**Ingress TCP with TLS.** A tailnet peer connects to this node on port 443 and
gets a certificate issued for the node's MagicDNS name; the backend behind it
only ever speaks plain HTTP. The listen host is omitted, which is the one place
a bare `:port` is the correct spelling.

```sh
TSPM_IN_APP='tcp,:443,127.0.0.1:8080,tls=true,idle=5m'
```

**A UDP map.** Egress DNS to a tailnet resolver, with the default 60s idle left
in place:

```sh
TSPM_OUT_DNS='udp,127.0.0.1:53,resolver-1:53'
```

Ingress UDP is subject to one tsnet constraint: `ListenPacket` rejects wildcard
binds, because a datagram listener has no per-connection local address to reply
from. If you write `:5353` or `0.0.0.0:5353`, tsportmap substitutes one of the
node's own tailnet addresses at bind time and logs the address it actually
bound. `[::]` is read as a preference for the IPv6 stack when the node has an
address in both families.

```sh
TSPM_IN_DNS='udp,:5353,127.0.0.1:5353'
```

UDP is bounded: at most 4096 concurrent sessions per mapping, and datagrams
queued for a client whose onward dial has not yet completed are capped and then
dropped. Overflow is counted under `reason="session_cap"`. A single datagram
from a new source address mints a session, and nothing about UDP makes the
sender prove it exists first, so these caps are the difference between a bounded
worst case and unbounded growth.

---

## Required Tailscale setup

This is the number one first-run failure. tsportmap cannot detect a missing ACL
grant for you — a refused dial looks like a refused dial. Do this part first.

### 1. Mint a credential

Two options, both from the Tailscale admin console under **Settings → Keys**:

- **A tagged auth key.** Create it with the tag you intend to use (`tag:proxy`
  below) and mark it reusable if more than one instance will use it. A tagged
  node has **key expiry disabled**, which is what a relay expected to stay up
  for months needs; an untagged node's key expires and the relay stops working
  at an unpredictable future date.
- **An OAuth client.** Give it the `auth_keys` write scope and the tag. Pass the
  client secret (`tskey-client-…`) as `TSPM_AUTHKEY`; tsportmap detects the
  prefix and lets tsnet mint short-lived auth keys from it. `TSPM_TAGS` is then
  **mandatory** — tsportmap refuses to start without it, because a key minted
  from an OAuth client must be tagged.

Either way, set `TSPM_TAGS` to match the tag on the credential. Prefer
`TSPM_AUTHKEY=file:/run/secrets/…` over an inline value: the file form keeps the
credential out of `docker inspect`, out of your platform's environment
dashboard, and out of `/proc/<pid>/environ`.

### 2. Tag ownership and grants

In the admin console's **Access controls**, the tag must be declared and the
proxy node must be granted the traffic it will actually carry. Nothing in
tsportmap can substitute for this; without a grant, every egress dial fails at
the tailnet layer.

```jsonc
{
  // Who may apply the tag to a node. An auth key or OAuth client can only
  // create a tag:proxy node if its owner is listed here.
  "tagOwners": {
    "tag:proxy": ["autogroup:admin"],
    "tag:db":    ["autogroup:admin"],
  },

  "grants": [
    // EGRESS: the proxy may reach Postgres on database hosts. This is the
    // grant that a TSPM_OUT_* mapping needs. Name only the ports you mapped.
    {
      "src": ["tag:proxy"],
      "dst": ["tag:db"],
      "ip":  ["tcp:5432"],
    },

    // INGRESS: tailnet users may reach the ports the proxy publishes. This is
    // the grant that a TSPM_IN_* mapping needs.
    {
      "src": ["autogroup:member"],
      "dst": ["tag:proxy"],
      "ip":  ["tcp:443", "udp:5353"],
    },
  ],
}
```

Both directions need their own grant, and the ports in the grant must match the
ports in your mappings. A mapping whose port is absent from the grant binds
successfully, accepts a connection, and then fails on the onward dial — which
reads like a broken backend rather than a policy problem.

### 3. Only if you set `TSPM_ACCEPT_ROUTES=true`

Reaching an address that lives behind a subnet router, rather than on a peer
itself, takes three separate things and all three are required:

1. The subnet router advertises the route (`tailscale up --advertise-routes=…`).
2. The route is **approved**. Approve it by hand in the admin console under
   **Machines → the router → Edit route settings**, or declare an
   `autoApprovers` entry so it approves on advertisement:

   ```jsonc
   {
     "autoApprovers": {
       "routes": {
         "10.42.0.0/16": ["tag:subnet-router"],
       },
     },
   }
   ```

3. tsportmap **accepts** it: `TSPM_ACCEPT_ROUTES=true`. Approval on the router
   side and acceptance on this side are different switches; having one without
   the other silently yields no route.

You also need a grant whose `dst` covers the routed range, e.g.
`{"src": ["tag:proxy"], "dst": ["10.42.0.0/16"], "ip": ["tcp:5432"]}`.

tsportmap re-applies `RouteAll` after **every** start, and verifies it took
effect rather than assuming it did. This is not defensive noise: tsnet submits
prefs as `ipn.Options{UpdatePrefs}`, which clones wholesale and preserves only
`Persist`, so `RouteAll` reverts to false on every process start. A node that
worked yesterday and silently stopped routing after a restart is exactly the
failure that behaviour produces.

### 4. Only if you use `tls=true`

Ingress TLS terminates with the node's own Tailscale-issued certificate, which
requires **MagicDNS** and **HTTPS certificates** to be enabled for the tailnet
(admin console → **DNS**). Without both, the listener fails to obtain a
certificate at bind time.

One warning about certificates and node identity. A certificate is issued for
this node's MagicDNS name. If the node has no persistent state — an ephemeral
node, or a container whose state directory is discarded on deploy — it
registers with a fresh identity every time it starts, and if two instances
briefly coexist wanting the same hostname, MagicDNS hands one of them a numeric
suffix. Each new name is a new certificate request, and Let's Encrypt enforces
both duplicate-certificate and per-domain issuance limits. A deploy loop over an
identity-churning node is a reliable way to hit them, after which certificate
issuance fails for a while and ingress TLS is simply down. If you use `tls=true`,
give the node durable state.

---

## Why the destination guard exists

Suppose you write an egress mapping and typo the target:

```sh
TSPM_OUT_POSTGRES='tcp,0.0.0.0:5432,db-l:5432'   # "db-l", not "db-1"
```

The intuition is that this fails: `db-l` is not a peer on your tailnet, so the
dial should error and you should see it immediately. **It does not fail.**
tsnet's dialer does not fail closed. When a destination is neither a known peer
nor covered by an accepted route, the dial falls through to a plain `net.Dialer`
on the container's own network — the same resolver, the same routes, the same
reachability as any other process in that container.

On a laptop that fallthrough usually produces a connection error and you notice.
On a PaaS it usually does not. These networks are dense with RFC1918 addresses
that answer: Render's private network is `10.x`, a typical Kubernetes pod network
is too, and Docker's default bridge is `172.17.0.0/16`. Your typo resolves
against the platform's own service discovery, connects to a *neighbouring
service of yours* that happens to answer on that port, and the
relay proceeds to shuttle bytes to it perfectly happily. Wrong backend, no
error, no log line, and a client that is talking to the wrong database while
reporting success. That is a much worse failure than an outage, because nothing
in the system knows anything is wrong.

The guard closes that hole. Before each egress dial, tsportmap asks the node's
own local API whether the target is a tailnet peer — by MagicDNS short name,
FQDN or IP — or falls inside a subnet route this node has actually accepted. If
it cannot place the destination in the tailnet, the dial is refused with
`ErrNotTailnet` and counted under `reason="not_tailnet"`, and the log line
explains which of the several possible reasons applied: unknown name, stale
Tailscale address belonging to no current peer, or an address inside an
advertised route that this node has not accepted. A peer that is merely
*offline* is still allowed through, because that dial fails loudly on its own
and loud failure is the outcome the guard is protecting.

Notes on the checking itself: only the tailnet peer set is consulted as a name
source. A name that only the container's resolver knows is precisely the case
this refuses. The netmap is read fresh on every dial rather than cached, because
a stale "yes" is the wrong answer to keep. Exit-node default routes are ignored
when matching routes, since accepting them would make every address on the
internet — and every address on the container's own network — look like a
tailnet destination.

**The guard defaults on** (`TSPM_REQUIRE_TAILNET_DEST=true`). Setting it to
`false` restores tsnet's native behaviour: unresolvable targets get dialled on
the container's local network instead of failing. There are legitimate reasons
to do that — reaching something over an accepted route the netmap does not
describe well, or debugging — but it is a real loss of a real safety property,
and tsportmap logs a warning at startup for as long as it is off.

---

## Platform notes

| Platform | Status | What to know |
| --- | --- | --- |
| **Docker / Compose** | Works | Bind `out` mappings to `0.0.0.0` inside the container so sibling containers and published ports can reach them, and control exposure with `-p 127.0.0.1:…` and `allow=`. Mount a named volume at `TSPM_STATE_DIR` to keep the node identity across `compose down`. No capabilities needed at all: `cap_drop: ALL`, `read_only: true` plus a tmpfs for `/tmp`. See [`deploy/docker-compose.yml`](deploy/docker-compose.yml). |
| **Render** | Works | Deploy as a **private service** (`type: pserv`), not a web service. See the constraints below. [`deploy/render.yaml`](deploy/render.yaml). |
| **Fly.io** | Works | The 6PN private network is **IPv6-only**: bind `out` mappings to `[::]:port`, never `0.0.0.0`. Turn off machine auto-stop — a relay that is asleep is a relay that is down, and tsnet has to re-establish its session on every wake. A Fly volume attaches to one machine, so state and multi-machine scaling are mutually exclusive; with more than one machine, use `TSPM_EPHEMERAL=true` and distinct hostnames. |
| **Railway** | Works | Private networking is **IPv6-only**: bind `[::]:port`. Private DNS names take a moment to become resolvable after a deploy, so an egress target on the Railway side may fail the first dial or two after a restart. A volume pins the service to one replica. |
| **Kubernetes** | Works, but | Use the [Tailscale operator's `ProxyGroup` egress](https://tailscale.com/kb/1438/kubernetes-operator-cluster-egress) instead unless you have a specific reason not to. It does per-port `matchPort`/`targetPort` mappings, it is supported, and it fits the rest of your manifests. If you do run tsportmap here, give it a PVC for `TSPM_STATE_DIR` (or set `TSPM_EPHEMERAL=true`), and match `runAsUser: 65532` to the image's UID. |
| **Vercel** | **Not supported** | Not a networking limitation — a process-lifecycle one. Vercel runs functions, which are invoked per-request and frozen or torn down between invocations. tsportmap needs an always-on process holding open listening sockets that sibling workloads connect to over a raw TCP or UDP socket. There is nowhere in that execution model for such a process to live, and no address at which siblings could reach it if there were. This is not a configuration problem and there is no workaround; run tsportmap on something that runs containers, and reach it from Vercel over the public internet or through Tailscale directly. |

### Render specifics

- **IPv4-only private network.** Bind `out` mappings to `0.0.0.0`. A `[::]` bind
  opens a socket nothing can ever connect to, and the deploy still looks
  healthy.
- **Private services support many ports.** You are not limited to one, which is
  what makes several mappings on one node practical.
- **Health checks work differently.** `healthCheckPath` applies to web services.
  A private service is judged live by whether it has opened a TCP port; nothing
  fetches a path. tsportmap's `/healthz` and `/readyz` are still worth curling
  from a sibling service, but they are not what gates a deploy. Render also
  waits for at least one open port before marking a deploy live, and injects a
  `PORT` variable that tsportmap ignores — there is no implicit listener, every
  port comes from a declared mapping. If your node has only ingress mappings,
  bind `TSPM_METRICS_ADDR` to `0.0.0.0:9090` so there is a port for Render to
  find.
- **Attaching a disk costs two things.** A Render disk attaches to exactly one
  instance, so the service can never scale past `numInstances: 1`, and deploys
  stop being zero-downtime — Render must stop the running instance before the
  replacement can mount the disk, so every mapping is down for the gap. The
  alternative is no disk plus `TSPM_EPHEMERAL=true`, which deploys cleanly but
  registers a new node identity every time; see the certificate warning above
  before choosing it for a `tls=true` node.
- **Region must match.** The private network does not span regions and there is
  no error for getting it wrong — the name simply does not resolve.

---

## Known limitations, and things to measure before you trust it

Read this section as the honest list of what will bite you.

- **Throughput is unmeasured here and is a known upstream constraint.** No
  benchmarks have been run on tsportmap, and none are claimed. What is known is
  that userspace networking mode — which is what `tsnet` is — has materially
  lower throughput than the kernel client, and that this is an open upstream
  issue: [tailscale/tailscale#9707](https://github.com/tailscale/tailscale/issues/9707).
  If you are moving bulk data, measure on your own hardware with your own
  traffic before committing to this design.
- **Idle memory badly understates loaded memory.** gVisor's netstack auto-tunes
  its send and receive buffers per connection, and they grow into the
  multi-megabyte range on a fast, high-bandwidth-delay path. A node sitting at a
  few tens of megabytes with no traffic can be an order of magnitude larger with
  a few dozen busy connections. Size the container against measured *loaded*
  memory, not against what it uses at rest, and expect the working set to scale
  with concurrent sessions rather than with configured mappings.
- **Long-lived idle connections get reset.** Platform NAT and load balancers
  reap idle flows on their own schedule, typically minutes, and the reset is not
  always propagated politely. This is a property of the network path, not of
  tsportmap. Clients must reconnect with backoff; a connection pool with a
  max-lifetime shorter than the platform's idle timeout avoids the problem
  entirely. Setting `idle=` on a mapping makes the reaping deterministic and
  observable on your side instead of mysterious on theirs.
- **Configuration changes require a restart.** There is no reload signal and no
  configuration API. Mappings are read once at startup and bound before the
  process reports ready. On a platform where a restart means a redeploy, and
  especially where a disk forces a hard cutover, plan changes accordingly.
- **The status endpoints are unauthenticated.** `/metrics` discloses every
  mapping name and its byte counters, which is a description of your private
  topology. The default bind is loopback for that reason; widening it should be
  a deliberate act on a network you trust.
- **One node, one process.** There is no clustering and no shared state. Two
  instances are two independent nodes, and if both want the same hostname,
  MagicDNS will suffix one of them.
- **UDP is best-effort by construction.** Sessions are capped at 4096 per
  mapping and pending datagrams for an unfinished dial are dropped on overflow.
  Both are visible in `tsportmap_rejected_total{reason="session_cap"}`.

---

## Building from source

Requires Go 1.26.6 or newer; `GOTOOLCHAIN=auto` (the default) fetches the exact
patch release named in `go.mod` if your toolchain is older.

```sh
go build ./...                    # build everything
make build                        # build the tsportmap binary
make test                         # go test -race ./...
make lint                         # go vet + gofmt check
make cover                        # coverage summary
make docker                       # build the container image
```

To run one package's tests:

```sh
go test ./internal/config/...
```

`-race` is not optional in CI and should not be optional locally: every relay
session is a pair of goroutines sharing a session table and a metrics recorder,
which is exactly what the detector exists to find. A green run without it says
very little.

The container image is built from a distroless static base and runs as UID
65532. It cross-compiles from the native build platform rather than emulating
the target, so a multi-arch build costs no QEMU.

## Contributing

Issues and pull requests are welcome. A few standing constraints, so a change
does not have to be turned away after it is written:

- **`tailscale.com` is the only third-party dependency and stays that way.**
  Everything else is the standard library — including the metrics exposition,
  the flag parsing and the configuration parsing. CI fails the build if
  `go mod tidy` produces a diff.
- **Table-driven tests, and test the failure paths.** Most of what this tool
  exists to get right is a failure mode; a test suite that only covers the happy
  path would not have caught any of them.
- **Comments explain why, not what,** and are written to stay true. No
  references to phases, timelines, or what the code used to do.
- **`gofmt`, `go vet`, and `go test -race ./...` must be clean** before a pull
  request is opened. `make all` runs all three.

Licensed under the [MIT License](LICENSE).
