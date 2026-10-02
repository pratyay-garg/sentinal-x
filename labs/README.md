# Practice targets (optional, separate from the product)

These are **intentionally vulnerable** applications used only to exercise the
scanner during development and demos. They are **not** part of SENTINAL X: the
product's code and Compose files contain no reference to them. They run in their
own Compose project (`sentinalx-labs`) with their own network.

> ⚠️ Run these only on a machine you control. They are deliberately insecure.

| Target | Browse at | Notes |
|---|---|---|
| OWASP Juice Shop | http://localhost:3000 | Links its pages with ordinary anchors; scan the base URL. |
| DVWA | http://localhost:8080 | Login-gated; complete the one-time DB setup in the browser first. |
| bWAPP | http://localhost:8090 | Login-gated; run the one-time install (`/install.php?install=yes`) first. |

## Start / stop

```bash
docker compose -f labs/docker-compose.yml up -d
docker compose -f labs/docker-compose.yml down
```

## Pointing a scan at a lab target

The product's workers run in Docker (project `sentinalx`). To let them reach
these containers by name, attach the lab containers to the product network once
they are both up:

```bash
for c in juice-shop dvwa bwapp; do
  docker network connect sentinalx_default sentinalx-labs-$c-1 2>/dev/null || true
done
```

Then add the hostnames to `SCOPE_ALLOWLIST` in `backend/.env` (recreate the app
services afterwards) and scan them like any other authorised target, e.g.
`http://juice-shop:3000/`, `http://dvwa/`, `http://bwapp/`.

Alternatively, scan the published host ports directly
(`http://host.docker.internal:3000/` etc.); on Docker Desktop/WSL2 the
container→host→container hop can be unreliable, so the network-connect approach
above is preferred.

## Authenticated scanning

Use the New Scan form's **Form login** (DVWA, bWAPP) or **API/JSON login**
options — the scanner logs itself in and verifies the session. The
`scripts/dvwa_session.sh` / `scripts/bwapp_session.sh` helpers here print a
ready-made cookie for the **Manual cookie / headers** option if you prefer.
