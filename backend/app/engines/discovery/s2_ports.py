"""
S2 — Active port + service/banner discovery. naabu piping straight into nmap
via -nmap-cli in one invocation. IMPLEMENTATION_SPEC_v4.md §5/§10 risk #19:
naabu's default SYN scan needs CAP_NET_RAW/CAP_NET_ADMIN in Docker; this
module feature-detects that and falls back to an unprivileged connect scan
rather than failing the stage.
"""
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET

from app.core.config import settings
from app.core.subprocess_utils import ToolNotFoundError, run_tool

logger = logging.getLogger(__name__)


async def _naabu_supports_syn_scan() -> bool:
    """Cheap capability probe: try a SYN-mode naabu invocation against
    localhost with a tiny timeout. If it errors in a way that smells like a
    permissions problem, fall back. This is intentionally conservative —
    false-negative (falls back to connect scan when SYN would have worked)
    is harmless; false-positive (assumes SYN works when it doesn't) wastes
    an entire scan attempt.
    """
    try:
        result = await run_tool(
            [settings.naabu_bin, "-host", "127.0.0.1", "-p", "1", "-silent"],
            timeout=5,
        )
    except ToolNotFoundError:
        return False
    stderr = result.stderr.decode(errors="ignore").lower()
    if "operation not permitted" in stderr or "permission denied" in stderr:
        return False
    return True


async def run_s2_port_scan(host: str) -> dict:
    """Returns {"services": [{"port": int, "protocol": str, "banner": str|None,
    "product": str|None, "version": str|None}]}. Degrades to an empty list on
    total tool failure — S3 onward can still run against port 80/443 guesses
    if the caller chooses, but that fallback is out of scope for this module;
    log loudly instead.
    """
    scan_type_args = []
    if not await _naabu_supports_syn_scan():
        logger.warning(
            "naabu SYN scan unavailable (missing CAP_NET_RAW/CAP_NET_ADMIN?) — "
            "falling back to unprivileged connect scan, which is slower and "
            "slightly noisier. Grant capabilities in docker-compose.yml to "
            "restore full-speed scanning."
        )
        scan_type_args = ["-scan-type", "connect"]

    argv = [
        settings.naabu_bin,
        "-host", host,
        "-top-ports", str(settings.naabu_top_ports),
        "-silent",
        *scan_type_args,
        "-nmap-cli", f"{settings.nmap_bin} -sV -sC --host-timeout {settings.nmap_host_timeout_seconds}s -oX -",
    ]

    try:
        result = await run_tool(argv, timeout=settings.naabu_timeout_seconds)
    except ToolNotFoundError:
        logger.error("naabu binary missing — check the Docker image build")
        return {"services": []}

    if result.timed_out:
        logger.warning("S2 timed out for host=%s", host)
        return {"services": []}

    return {"services": _parse_nmap_xml(result.stdout.decode(errors="ignore"))}


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    """naabu's -nmap-cli prints naabu's own status lines interleaved with the
    nmap XML on stdout when -oX - is used; extract just the <nmaprun>...
    </nmaprun> block before parsing.
    """
    match = re.search(r"<\?xml.*?</nmaprun>", xml_text, re.DOTALL)
    if not match:
        return []

    services: list[dict] = []
    try:
        root = ET.fromstring(match.group(0))
    except ET.ParseError:
        logger.warning("failed to parse nmap XML output from naabu -nmap-cli")
        return []

    for host_el in root.findall("host"):
        for port_el in host_el.findall("./ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            port_id = port_el.get("portid")
            if port_id is None or not port_id.isdigit():
                continue
            confidence_raw = service_el.get("conf") if service_el is not None else None
            services.append({
                "port": int(port_id),
                "protocol": port_el.get("protocol", "tcp"),
                "application_protocol": service_el.get("name") if service_el is not None else None,
                "tunnel": service_el.get("tunnel") if service_el is not None else None,
                "banner": _format_banner(service_el),
                "product": service_el.get("product") if service_el is not None else None,
                "version": service_el.get("version") if service_el is not None else None,
                "confidence": (
                    int(confidence_raw) / 10
                    if confidence_raw is not None and confidence_raw.isdigit()
                    else None
                ),
            })
    return services


def _format_banner(service_el) -> str | None:
    if service_el is None:
        return None
    parts = [service_el.get(k) for k in ("product", "version", "extrainfo") if service_el.get(k)]
    return " ".join(parts) if parts else service_el.get("name")
