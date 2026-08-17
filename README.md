# ht-autocert v2

Multi-tenant certificate lifecycle automation for Cisco IOS-XE voice gateways.
Issues certificates from any ACME CA using Cloudflare DNS-01, escrows the
private key, packages it as PKCS12, and deploys it to Cisco Catalyst 8200 gateways with
an API-first blue/green trustpoint cutover — with a web console, a scheduler and a CLI on
top.

This replaces the original Ansible implementation (certbot + an EEM applet)
entirely. That version lives in the `ht-wxcautocert` repository; nothing here
depends on it.

---


## Quick start

Requires [Docker Engine](https://docs.docker.com/engine/install/) and the
Compose v2 plugin (`docker compose version`).

```bash
cp .env.htac.example .env.htac
docker compose up -d --build
```

All commands below use the `./htac` wrapper in this directory. It runs the CLI
inside the Docker container against the same `htac-data` volume as the web
console and scheduler — so there is one datastore, not a host copy and a
container copy.

Generate a master key and keep it somewhere durable:

```bash
./htac gen-master-key
```

**Back it up somewhere durable before going further.** This key wraps every
escrowed gateway private key in the datastore; if it is lost, those keys cannot
be recovered and every certificate has to be re-issued. A file on one laptop is
not a backup.

Paste the key into `.env.htac` as `HTAC_MASTER_KEY`, set
`HTAC_CLOUDFLARE_API_TOKEN`, then recreate the container so it picks up the new
env:

```bash
docker compose up -d
./htac init
```

Check the configuration at any point — this verifies the master key actually
opens everything stored, which is otherwise only discovered mid-deployment:

```bash
./htac doctor
```

Register a CA. Start on staging — Let's Encrypt production rate limits are shared
across `managedcollab.com` for the whole fleet:

```bash
./htac ca add --name letsencrypt-staging --email ops@example.com --staging
```

ZeroSSL requires External Account Binding (get the KID/HMAC from the ZeroSSL
dashboard):

```bash
./htac ca add --name zerossl --email ops@example.com --directory-url https://acme.zerossl.com/v2/DV90 --eab-kid <kid> --eab-hmac <hmac>
```

Add a tenant:

```bash
./htac tenant add --slug husd --name "HUSD" --domain-suffix husd.clients.managedcollab.com --ca letsencrypt-staging
```

Then add devices — from Webex Control Hub (see *Discovering gateways* below),
one at a time:

```bash
./htac device add --tenant husd --hostname vg01 --fqdn vg01.husd.clients.managedcollab.com --address 10.0.0.1
```


Check state, then issue:

```bash
./htac status
```

```bash
./htac issue --dry-run
```

---

## Deploying (Phase 2)

Store credentials once per tenant, overriding per device where they differ:

```bash
./htac tenant set-credentials husd --username netadmin
```

Check what a gateway currently holds:

```bash
./htac device inspect brg-vgw-01.husd.clients.managedcollab.com
```

Then deploy. Import and verification happen against the **idle** trustpoint; the
one bound in `sip-ua crypto signaling` is not touched until the new certificate
is confirmed present:

```bash
./htac deploy --fqdn brg-vgw-01.husd.clients.managedcollab.com
```

To stage a certificate ahead of a maintenance window without cutting over:

```bash
./htac deploy --fqdn brg-vgw-01.husd.clients.managedcollab.com --no-rebind
```

### The cutover sequence

```
read state  →  upload .p12  →  clear IDLE trustpoint  →  import
            →  set revocation-check  →  VERIFY cn + serial on device
            →  bind sip-ua  →  verify binding  →  write memory  →  delete .p12
```

If verification fails, the old trustpoint is still bound and still serving — the
run aborts with the device untouched. If the rebind itself does not take, the
previous trustpoint is restored automatically. The `.p12` is removed from flash
whether the run succeeded or failed, since a bundle left on flash is an offline
attack on the escrowed key.

This is the inverse of the EEM applet, which ran `no crypto pki trustpoint` and
`crypto key zeroize rsa` *before* attempting the import — so a bundle the device
could not parse left a survivability gateway with no key and no trustpoint.

### Upgrading an existing database

Phase 2 adds credential and transport columns:

```bash
./htac migrate
```

---

## Things to verify on your gateways

Three items I could not confirm remotely. Each is a one-line check.

**1. PKCS12 profile on 17.15.3a.** Both `.p12` files I inspected carry a
SHA-256 MAC — the OpenSSL 3 default profile. That profile is documented as
failing to import on IOS-XE 17.09.x (the device creates the trustpoint, imports
the key, deletes everything, and logs `%PKI-3-PKCS12_IMPORT_FAILURE ... Reason:
Unknown reason`). 17.15.3a may well accept it. If an import fails, switch the
device to the legacy profile:

```bash
./htac device add ... --p12-profile legacy
```

**2. `revocation-check` on the trustpoint.** The Webex template specifies
`revocation-check crl`. Let's Encrypt turned off OCSP in 2025 and its leaf certs
carry no CRL distribution point IOS can use, so peer validation against that
trustpoint can fail. `revocation-check none` is the usual setting for an
LE-issued identity trustpoint. Phase 2 manages this as asserted config.

**3. Which chain your devices should carry.** Let's Encrypt is migrating from
ISRG Root X1 to ISRG Root YR — the `YR2.txt` / `YR_ISRG.txt` files in your
Downloads are the new intermediate and root. Set `--preferred-chain` on the CA
profile once you know which root Webex trusts. Every issued certificate records
the chain that shipped, so a rollover is visible in `./htac status`.

---

## Web console and scheduler

The `docker compose up` from Quick Start serves the console on
`127.0.0.1:8866` (override with `HTAC_HOST_PORT`) and runs the scheduler in the
same process. Sign in with `HTAC_API_TOKEN`.

The console shows fleet state, per-device certificate history, live device
state read through IOS-XE RESTCONF, and run history. It can issue and deploy on demand —
including the stage-only (`--no-rebind`) path. Tenants, CA profiles and
credentials stay CLI-only, so secrets are never entered into or returned by the
web API.

After changing application code, rebuild and restart:

```bash
docker compose up -d --build
```

### Renewal spreading

The scheduler runs **daily**, not monthly. Each device gets a stable renewal
offset derived from its FQDN, added to the tenant threshold — so gateways
provisioned on the same day drift apart instead of renewing in a herd.

Every tenant shares one registered domain (`managedcollab.com`), and Let's
Encrypt caps **50 certificates per registered domain per week**. Simulated over
50 gateways all issued on the same day, across two years:

| `renewal_spread_days` | Peak certificates in one week |
|---|---|
| 0 (no spread) | **50** — exactly at the cap |
| 7 | 35 |
| 14 | 27 |
| **21 (default)** | **17** |
| 28 | 16 |

Past 21 days there is no further gain. Steady state is roughly 6–8 certificates
a week, so at your fleet size the rate limit is not a binding constraint — the
spread exists to keep a bulk onboarding or mass re-issue from clustering.

---

## Tests

```bash
./scripts/test.sh
```

119 tests, no network or device access required. Coverage focuses on the parts
that failed silently in the Ansible version: PKCS12 encoding profiles, renewal
boundaries, chain selection, DNS cleanup on failure, the encryption's record
binding, `show` output parsing, renewal spread under the rate limit, the API's
secrets boundary, and — most importantly — the deployment safety invariants
(rejected bundle, wrong serial, failed rebind, cleanup on failure).

The test image also builds the frontend (`npm run build`), so TypeScript errors
fail CI even though the test container does not serve the SPA.

---

## Needs validation against real hardware

Everything above is tested against a simulated device. Three things can only be
confirmed on a real 17.15.3a gateway:

1. **Interactive prompt wording.** `no crypto pki trustpoint` and PKCS12 import
   prompt for confirmation, and the exact wording varies by train. The patterns
   are constants at the top of [app/devices/ssh.py](app/devices/ssh.py) and every
   interaction ends on a returned prompt rather than an exact match, but they
   should be checked against one device before a fleet run.
2. **RESTCONF oper paths.** `Cisco-IOS-XE-crypto-pki-oper:crypto-pki-oper-data`
   is read from the published model and is enabled by default. Validate the
   native model paths against the installed IOS-XE train.
3. **PKCS12 profile**, as above.

Run `./htac deploy --fqdn <one-device> --no-rebind` first. It imports and verifies
without cutting over, so the riskiest step is exercised with nothing at stake.

---

## Not yet built

- **Alerting.** Failures land in the run log and the console; nothing pushes to
  email/Webex yet.

---

## Running in Docker

Everything runs in Docker — there is no supported host Python or Node workflow.
The sections below cover production deployment, gateway connectivity, and
operational details beyond Quick Start.

Console on `127.0.0.1:8866`, scheduler in the same container. Sign in with
`HTAC_API_TOKEN` from `.env.htac`.

### Deploying to a public Docker VPS

The repository includes a VPS overlay with Caddy as the TLS reverse proxy. It
obtains and renews the public HTTPS certificate automatically; the application
container remains unprivileged and is not directly exposed to the internet.

On a new Ubuntu/Debian VPS, install Docker Engine and the Compose v2 plugin,
then clone this repository. In the repository directory:

```bash
cp .env.htac.example .env.htac
chmod 600 .env.htac
openssl rand -base64 32   # use as HTAC_MASTER_KEY
openssl rand -base64 32   # use a different value as HTAC_API_TOKEN
```

Fill in at least these settings:

```dotenv
HTAC_DOMAIN=autocert.example.com
HTAC_MASTER_KEY=...
HTAC_API_TOKEN=...
HTAC_CLOUDFLARE_API_TOKEN=...
HTAC_WEBEX_CLIENT_ID=...
HTAC_WEBEX_CLIENT_SECRET=...
HTAC_WEBEX_REDIRECT_URI=https://autocert.example.com/auth/callback
HTAC_WEBEX_ALLOWED_DOMAINS=example.com
HTAC_BOOTSTRAP_ADMINS=admin@example.com
```

Before starting, create an `A` record (and `AAAA` only if IPv6 works on the
VPS) for `HTAC_DOMAIN`, pointing to the VPS. Allow inbound TCP 22, 80 and 443
and UDP 443 in both the provider firewall and the host firewall. Do **not**
publish the application port 8000.

Deploy, migrate the datastore, wait for Docker health, test HTTPS and run the
application diagnostics with one command:

```bash
chmod +x scripts/vps-deploy.sh scripts/vps-smoke-test.sh
./scripts/vps-deploy.sh
```

The final line should report that `https://<HTAC_DOMAIN>` is healthy. If it
does not, inspect both services:

```bash
docker compose --env-file .env.htac \
  -f docker-compose.yml -f docker-compose.vps.yml ps
docker compose --env-file .env.htac \
  -f docker-compose.yml -f docker-compose.vps.yml logs --tail=200
```

For Webex OAuth, register the exact HTTPS callback shown above in the Webex
integration. A mismatch in scheme, hostname, path, or trailing slash is
rejected before deployment by the script.

After the first start, bootstrap the application:

```bash
./htac init
./htac doctor
```

Re-run `./scripts/vps-deploy.sh` after pulling an update. Named volumes preserve
the SQLite datastore and Caddy state across rebuilds. Back up `htac-data` and
store `HTAC_MASTER_KEY` separately; neither is useful for recovery without the
other.

If the host already has Nginx Proxy Manager (or another reverse proxy) on 80/443,
do not use `scripts/vps-deploy.sh` — that overlay starts Caddy on those ports.
Keep the app on loopback (`HTAC_BIND=127.0.0.1`) and proxy to port 8866.

### GitHub Actions (build and deploy)

Pushes to `main` run three jobs:

1. **test** on GitHub-hosted runners (`docker compose --profile test` plus an image build)
2. **publish** the runtime image to `ghcr.io/<owner>/ht-autocert` (`latest` and `sha-<commit>`)
3. **deploy** on a self-hosted runner labeled `htac` at `/opt/ht-autocert`. It
   resets the checkout to `origin/main`, pulls that commit's image, migrates,
   and restarts. Pull requests never run on that runner.

GitHub-hosted runners cannot reach this VPS, so deploy is not SSH from
`ubuntu-latest`. The runner user needs Docker and write access to
`/opt/ht-autocert`. Local `docker compose up --build` still tags
`ht-autocert:latest` unless `HTAC_IMAGE` is set. Install the runner once as
root with `RUNNER_TOKEN=<token> ./scripts/install-github-runner.sh` (token from
GitHub → Settings → Actions → Runners).

### Before it will reach your gateways

A container has no `~/.ssh/known_hosts`, so strict host key checking fails for
every device unless the key is pinned with the device record. Do this once per
gateway, comparing the fingerprint against the device before accepting:

```bash
./htac device trust brg-vgw-01.husd.clients.managedcollab.com
```

`./htac doctor` reports any device still missing a pinned SSH host key.

### Moving an existing datastore into the volume

```bash
docker compose cp data/htac.db htac:/srv/data/htac.db
```

`docker compose cp` writes as root, but the container runs as uid 10001, so fix
ownership afterwards or the app starts and dies with
``attempt to write a readonly database``:

```bash
docker compose run --rm --user root --entrypoint sh htac -c 'chown -R 10001:10001 /srv/data'
```

### Before exposing it on a server

The console can issue and deploy certificates across the whole fleet and
authenticates with a single bearer token, so it publishes to loopback only by
default.

- **Terminate TLS in front of it.** The bearer token is sent on every request;
  over plain HTTP on a shared network it is readable in transit.
- Change the port mapping to `8080:8000` only once a reverse proxy is in place.
- Host port 8080 rather than 8000: Portainer's edge agent uses 8000, and the
  collision only shows up as a container that will not start.
- **Back up the `htac-data` volume.** It holds every escrowed private key.
  Treat the backup with the same care as `HTAC_MASTER_KEY` -- and note the
  backup is useless without that key, and the key is useless without it.
- The container needs routed access to gateway management addresses, plus
  outbound HTTPS to the ACME CA and the Cloudflare API.

---

## Reaching on-prem gateways from hosted infrastructure

The tunnel runs as a **sidecar**, and the application joins its network
namespace (`network_mode: service:<sidecar>`). Two reasons not to put the client
inside the app image:

1. `NET_ADMIN` and `/dev/net/tun` stay on the sidecar. The container holding
   every escrowed private key does not get to reconfigure network interfaces.
2. Connectivity becomes swappable — changing vendor is a compose change, not an
   application rebuild.

### Twingate (recommended)

```bash
export HTAC_COMPOSE_OVERLAY="docker-compose.twingate.yml"
docker compose -f docker-compose.yml -f docker-compose.twingate.yml up -d
```

With the stack running, `./htac` execs into the same network namespace as the
Twingate sidecar automatically. Set `HTAC_COMPOSE_OVERLAY` whenever you use an
overlay so one-off `./htac` commands route through the tunnel too.

In the Twingate admin console: create a Service Account, generate its key, save
the JSON verbatim to `./secrets/twingate.json`, and assign it Resources covering
your gateway management subnets. Set `TWINGATE_NETWORK` in `.env.htac`.

Twingate routes whole subnets, so all fifty gateways keep their real management
addresses and nothing in the application changes.

### Cloudflare Tunnel (alternative)

```bash
export HTAC_COMPOSE_OVERLAY="docker-compose.cloudflared.yml"
docker compose -f docker-compose.yml -f docker-compose.cloudflared.yml up -d
```

Worth understanding before choosing it: `cloudflared access tcp` is a
*per-hostname port forwarder*. Each gateway needs its own listener and local
port, and each device's address becomes a loopback port:

```bash
./htac device add --tenant husd --hostname vg01 --fqdn vg01.husd.clients.managedcollab.com --address 127.0.0.1 --ssh-port 2201
```

Fine for a handful of devices, unpleasant at fifty. For routed subnet access via
Cloudflare you would use Tunnel private networks plus the WARP client in the
sidecar — the same architecture as Twingate, so pick whichever vendor you
already run.

---

## Webex OAuth sign-in

Create an integration at <https://developer.webex.com/my-apps>:

- **Redirect URI** must exactly match `HTAC_WEBEX_REDIRECT_URI`
- **Scopes**: `spark:people_read` for identity, plus the read-only admin scopes
  gateway discovery needs:

```
spark:people_read,spark-admin:organizations_read,spark-admin:telephony_config_read
```

Comma-separated, because `.env.htac` is read by Docker Compose's `env_file`
parser and a space-separated value can be ambiguous. They are normalised to
spaces before being sent to Webex, so either form works.

Every scope is read-only. The console never writes to Control Hub.

Then set `HTAC_WEBEX_CLIENT_ID`, `HTAC_WEBEX_CLIENT_SECRET`, and
`HTAC_WEBEX_REDIRECT_URI`.

Discovery uses the signed-in user's own token rather than a service credential,
so it reads exactly what that person's Control Hub rights allow, Webex attributes
the reads to a real person, and revoking them in Control Hub revokes this too.
The trade-off is that the token has to outlive the request that fetched it, so
it is sealed with the vault like escrowed key material, bound to the user's
email, never returned through the API, and deleted on sign-out.

**You must also set an access policy.** Authentication proves who someone is;
it does not prove they work for you. Any Webex user in the world can complete a
sign-in against a public integration, so with no policy configured every login
is refused:

```
HTAC_WEBEX_ALLOWED_DOMAINS=hyetechnetworks.com
HTAC_WEBEX_ALLOWED_EMAILS=
HTAC_WEBEX_ALLOWED_ORG_ID=
```

### Roles

A domain allowlist lets **everyone at the company** sign in. That is the right
gate for authentication and the wrong one for authority: on a console that can
redeploy certificates to client voice gateways, "works here" must not imply
"may change production". So access is two layers.

`HTAC_WEBEX_ALLOWED_DOMAINS` decides who may *sign in*. Explicit grants decide
what they may *do*:

| Role | Can |
|---|---|
| `viewer` | Read fleet state, certificate history, run history, live device state |
| `operator` | + issue, deploy, run the renewal cycle |
| `admin` | + manage who else has access |

```bash
./htac operator add engineer@hyetechnetworks.com --role operator
```

```bash
./htac operator list
```

Signing in without a grant gets an explicit "you have no role" rather than a
console where every action fails. `HTAC_WEBEX_DEFAULT_ROLE` defaults to `none`;
setting it to `viewer` opens read access to everyone who passes the sign-in
gate, and `doctor` warns when it is set. Set `HTAC_BOOTSTRAP_ADMINS` to at
least one address so a fresh deployment is reachable before any grant exists.

Revoking a grant takes effect on the next request -- the session cookie stays
cryptographically valid, but the grant behind it is re-checked every time.

The API token keeps working alongside and carries **admin** (holding it is
equivalent to server-side access), so the CLI, cron and scripts are
unaffected. Sessions are signed cookies (`HttpOnly`, `SameSite=Lax`, `Secure`
unless disabled) valid for `HTAC_SESSION_TTL_HOURS`, signed with a key derived
from the master key and domain-separated from the vault.

---

## Discovering gateways from Control Hub

There is no "gateway" resource in the Webex API. A Local Gateway is the
premises end of a **trunk**, so `/telephony/config/premisePstn/trunks` is the
only place an enrolled gateway appears. `/devices` holds phones and room
endpoints, not gateways.

Two properties of that API shape what discovery can and cannot do.

**The trunk list carries no addresses.** `GET .../trunks` returns id, name,
location, `inUse` and `trunkType` only. `address`, `domain` and `port` exist
only on the per-trunk detail call, so discovery is list-then-fan-out: one extra
request per trunk. A detail call that fails degrades that trunk to its summary
rather than failing the whole run.

**Only certificate-based trunks record an FQDN.** A `REGISTERING` trunk
authenticates with a SIP username and password, and Webex stores no address for
it at all. For those, Control Hub can tell you a gateway *exists* and what it is
called — not the name its certificate must carry. That name is derived from the
tenant's `domain_suffix` and flagged **derived — confirm** in the UI.

So an import is a worklist, not a deployable fleet. Imported devices are created
**disabled**, and the renewal scheduler skips disabled devices, so a
half-populated import can never be picked up by an unattended renewal.

### Each client is a separate Webex organisation

Every Control Hub call is org-scoped. A missing `orgId` silently reads the
partner's own organisation instead of the customer's, which is why the org is
selected explicitly in the toolbar and stored per tenant:

```bash
./htac webex orgs
```

```bash
./htac tenant set-webex-org husd --org-id <organisation id>
```

An organisation can be linked to only one tenant; the second attempt is refused
rather than quietly reassigning it.

### Importing

```bash
./htac webex trunks --tenant husd
```

Dry-run first — this lists what would be created and how each name was arrived
at:

```bash
./htac webex import --tenant husd
```

```bash
./htac webex import --tenant husd --apply
```

Then finish each device and enable it:

```bash
./htac device trust <fqdn>
```

```bash
./htac device set-credentials <fqdn>
```

In the web console the same flow is the **Discover** page, using the
organisation selected in the toolbar. The CLI takes a token via `--token` or
`WEBEX_TOKEN` (a personal access token from
<https://developer.webex.com/docs/getting-started> is enough, valid ~12h); the
console uses the signed-in user's own OAuth token.
