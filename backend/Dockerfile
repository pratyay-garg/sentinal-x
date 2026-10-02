# --- stage 1: build the ProjectDiscovery Go toolchain + nmap ---
FROM golang:1.26-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Reproducible scanner/toolchain inventory. Update deliberately and re-run the
# parser/CLI compatibility suite before changing any version.
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.16.0
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@v1.6.1
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.0
RUN git clone --depth 1 --branch v10.4.7 \
      https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates

# --- stage 2: runtime image ---
FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

# chromium powers katana's headless crawl. Do NOT pin an exact Debian patch
# version: Debian keeps only the newest security build in the bookworm mirror, so
# a pinned version silently disappears and breaks the image build weeks later
# (apt exit 100). Any current chromium works for headless crawling.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap libpcap0.8 ca-certificates chromium \
    && rm -rf /var/lib/apt/lists/*

# naabu's default SYN scan needs raw-socket capability. Prefer granting the
# capability at `docker run`/compose time (see docker-compose.yml) over a
# permanent setcap here, so the fallback `-scan-type connect` path (used when
# the capability isn't granted) stays exercised and tested, not dead code.

ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/projectdiscovery/bin:/opt/venv/bin:${PATH}"

WORKDIR /srv/backend
COPY backend/pyproject.toml backend/uv.lock ./
RUN pip install --no-cache-dir uv==0.11.16
RUN uv sync --frozen --no-dev --no-install-project

# Keep scanners in their own PATH entry ahead of the Python environment. The
# Python httpx distribution also installs an `httpx` console script; directory
# isolation makes it impossible for that package to replace the scanner.
COPY --from=tools /go/bin/subfinder /opt/projectdiscovery/bin/subfinder
COPY --from=tools /go/bin/dnsx      /opt/projectdiscovery/bin/dnsx
COPY --from=tools /go/bin/naabu     /opt/projectdiscovery/bin/naabu
COPY --from=tools /go/bin/httpx     /opt/projectdiscovery/bin/httpx
COPY --from=tools /go/bin/katana    /opt/projectdiscovery/bin/katana
COPY --from=tools /go/bin/nuclei    /opt/projectdiscovery/bin/nuclei
COPY --from=tools /opt/nuclei-templates /opt/nuclei-templates

RUN groupadd --system discovery \
    && useradd --system --gid discovery --create-home --home-dir /home/discovery discovery \
    && mkdir -p /data/evidence \
    && chown -R discovery:discovery /data/evidence /home/discovery

WORKDIR /srv
# The single application package: app/{core,schemas,models,graph,llm,engines/*,
# api routers, tasks}. Everything is one package now.
COPY backend/app ./app
COPY backend/migrations ./migrations
COPY backend/alembic.ini .
USER discovery

HEALTHCHECK --interval=10s --timeout=5s --retries=10 CMD \
    python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live')"

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
