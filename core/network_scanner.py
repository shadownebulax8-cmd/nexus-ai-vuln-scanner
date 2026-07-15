import asyncio
import socket
from typing import Any, Callable, Dict, List, Optional

# Signature database: maps a well-known port to the service commonly running
# there, a plain-English description of the typical exposure risk, and the
# closest OWASP Top 10 (2021) category for reporting purposes. This is a
# heuristic mapping for triage, not a CVE database.
VULNERABILITY_SIGNATURES: Dict[int, Dict[str, str]] = {
    21:    {"service": "FTP",          "issue": "Anonymous FTP access / plaintext authentication risk.", "owasp": "A05:2021-Security Misconfiguration"},
    22:    {"service": "SSH",          "issue": "Outdated SSH protocol/cipher support or brute-force exposure.", "owasp": "A07:2021-Identification and Authentication Failures"},
    23:    {"service": "Telnet",       "issue": "Unencrypted management stream; credentials sent in cleartext.", "owasp": "A02:2021-Cryptographic Failures"},
    25:    {"service": "SMTP",         "issue": "Open relay risk / unauthenticated mail submission.", "owasp": "A05:2021-Security Misconfiguration"},
    53:    {"service": "DNS",          "issue": "Exposed recursive resolver; potential for cache poisoning or amplification abuse.", "owasp": "A05:2021-Security Misconfiguration"},
    80:    {"service": "HTTP",         "issue": "Missing security headers (HSTS, X-Frame-Options) / cleartext transport.", "owasp": "A05:2021-Security Misconfiguration"},
    110:   {"service": "POP3",         "issue": "Unencrypted mail retrieval; credentials sent in cleartext.", "owasp": "A02:2021-Cryptographic Failures"},
    143:   {"service": "IMAP",         "issue": "Unencrypted mail access; credentials sent in cleartext.", "owasp": "A02:2021-Cryptographic Failures"},
    443:   {"service": "HTTPS",        "issue": "Potential legacy TLS negotiation (SSLv3/TLS1.0) or misconfigured cert chain.", "owasp": "A02:2021-Cryptographic Failures"},
    445:   {"service": "SMB",          "issue": "Exposed file-sharing service; historically a high-value ransomware vector.", "owasp": "A05:2021-Security Misconfiguration"},
    993:   {"service": "IMAPS",        "issue": "TLS-wrapped IMAP exposed externally; verify cipher suite strength.", "owasp": "A02:2021-Cryptographic Failures"},
    995:   {"service": "POP3S",        "issue": "TLS-wrapped POP3 exposed externally; verify cipher suite strength.", "owasp": "A02:2021-Cryptographic Failures"},
    1433:  {"service": "MSSQL",        "issue": "Remote database access exposed to external interfaces.", "owasp": "A05:2021-Security Misconfiguration"},
    1521:  {"service": "Oracle DB",    "issue": "Remote database listener exposed to external interfaces.", "owasp": "A05:2021-Security Misconfiguration"},
    2049:  {"service": "NFS",         "issue": "Exposed network filesystem; check export permissions.", "owasp": "A01:2021-Broken Access Control"},
    3306:  {"service": "MySQL",        "issue": "Remote database access exposed to external interfaces.", "owasp": "A05:2021-Security Misconfiguration"},
    3389:  {"service": "RDP",          "issue": "Exposed remote desktop; common brute-force and ransomware entry point.", "owasp": "A07:2021-Identification and Authentication Failures"},
    5432:  {"service": "PostgreSQL",   "issue": "Remote database access exposed to external interfaces.", "owasp": "A05:2021-Security Misconfiguration"},
    5900:  {"service": "VNC",          "issue": "Remote framebuffer access; often weak or absent authentication.", "owasp": "A07:2021-Identification and Authentication Failures"},
    6379:  {"service": "Redis",        "issue": "In-memory data store commonly deployed without authentication.", "owasp": "A05:2021-Security Misconfiguration"},
    8080:  {"service": "HTTP-Proxy",   "issue": "Exposed administrative console or proxy panel without access controls.", "owasp": "A01:2021-Broken Access Control"},
    8443:  {"service": "HTTPS-Alt",    "issue": "Alternate HTTPS management interface; verify it isn't a default/unpatched panel.", "owasp": "A05:2021-Security Misconfiguration"},
    9200:  {"service": "Elasticsearch", "issue": "Search/index engine often exposed without authentication by default.", "owasp": "A01:2021-Broken Access Control"},
    27017: {"service": "MongoDB",      "issue": "Document database historically exposed without authentication by default.", "owasp": "A01:2021-Broken Access Control"},
}

# Ports where the service stays silent until the client speaks first. We send
# a minimal, standard HEAD request purely to elicit response headers for
# fingerprinting -- the same passive technique curl/nmap -sV use.
_HTTP_PROBE_PORTS = {80, 443, 8000, 8080, 8443, 8888}

_UNKNOWN_SIGNATURE = {
    "service": "Unknown",
    "issue": "Generic open port. Unrecognized service should be identified manually.",
    "owasp": "General Exposure",
}


async def scan_single_port(
    target_ip: str,
    port: int,
    timeout: float = 1.0,
    banner_timeout: float = 0.6,
) -> Dict[str, Any]:
    """
    Asynchronously probes a single TCP port: attempts a handshake, optionally
    nudges HTTP-like services with a HEAD request, and grabs whatever banner
    is offered back.
    """
    try:
        conn = asyncio.open_connection(target_ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {"port": port, "status": "CLOSED"}

    banner = "Unknown Banner"
    try:
        if port in _HTTP_PROBE_PORTS:
            probe = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n".encode()
            writer.write(probe)
            await writer.drain()

        data = await asyncio.wait_for(reader.read(1024), timeout=banner_timeout)
        if data:
            raw = data.decode("utf-8", errors="ignore").strip()
            if raw:
                # Collapse multi-line banners (e.g. full HTTP headers) into a
                # single readable line instead of raw embedded newlines.
                banner = " | ".join(line.strip() for line in raw.splitlines() if line.strip())
    except Exception:
        pass  # No banner offered back by the host service -- not fatal.
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    vuln_details = VULNERABILITY_SIGNATURES.get(port, _UNKNOWN_SIGNATURE)

    return {
        "port": port,
        "status": "OPEN",
        "service": vuln_details["service"],
        "vulnerability": vuln_details["issue"],
        "owasp_category": vuln_details["owasp"],
        "banner_grabbed": banner,
    }


async def run_parallel_scan(
    target_host: str,
    ports: List[int],
    timeout: float = 1.0,
    banner_timeout: float = 0.6,
    max_concurrency: int = 250,
    on_port_done: Optional[Callable[[int, Dict[str, Any]], None]] = None,
) -> List[Dict[str, Any]]:
    """
    Orchestrates concurrent port probes across the given list, capped by a
    semaphore so scanning a wide port range doesn't exhaust local sockets.
    `on_port_done`, if given, is invoked after every single port finishes
    (open or closed) -- handy for driving a live progress bar.
    """
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        return [{"error": f"Failed to resolve host target domain: {target_host}"}]

    semaphore = asyncio.Semaphore(max_concurrency)

    async def _bounded_scan(port: int) -> Dict[str, Any]:
        async with semaphore:
            result = await scan_single_port(target_ip, port, timeout, banner_timeout)
        if on_port_done:
            on_port_done(port, result)
        return result

    tasks = [_bounded_scan(port) for port in ports]
    results = await asyncio.gather(*tasks)

    return [r for r in results if r.get("status") == "OPEN"]
