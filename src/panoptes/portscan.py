"""Port-scan recon for authorized testing.

Two backends, same interface:

  * **nmap** — if the system ``nmap`` binary is present, Panoptes shells out to
    it for a TCP connect + light service/version scan and parses the XML.
  * **connect** — otherwise, a pure-Python asyncio TCP *connect* scan of a
    curated port list (no raw sockets / root needed, no stealth techniques).

Both are single-target, scope-enforced (every host goes through
:meth:`Scope.check_host`), concurrency-limited and non-aggressive by default.
This is reconnaissance for *authorized* engagements — not a mass scanner.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass, field
from typing import List, Optional
from xml.etree import ElementTree as ET

from .models import Confidence, Finding, Severity
from .scope import Scope

# Curated default ports (common services), not all 65535.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5601: "kibana", 5900: "vnc", 5985: "winrm",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    8888: "http-alt", 9200: "elasticsearch", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongodb",
}

DEFAULT_PORTS = sorted(COMMON_PORTS)

# Services that are risky to expose; (severity, why).
_SENSITIVE = {
    "mysql": (Severity.MEDIUM, "database port reachable"),
    "postgresql": (Severity.MEDIUM, "database port reachable"),
    "mssql": (Severity.MEDIUM, "database port reachable"),
    "oracle": (Severity.MEDIUM, "database port reachable"),
    "mongodb": (Severity.HIGH, "MongoDB is often unauthenticated by default"),
    "redis": (Severity.HIGH, "Redis is often unauthenticated by default"),
    "memcached": (Severity.HIGH, "memcached has no auth and enables amplification"),
    "elasticsearch": (Severity.HIGH, "Elasticsearch often exposes data unauthenticated"),
    "rdp": (Severity.MEDIUM, "RDP exposed to the network"),
    "vnc": (Severity.MEDIUM, "VNC exposed to the network"),
    "telnet": (Severity.MEDIUM, "Telnet is cleartext"),
    "ftp": (Severity.LOW, "FTP is often cleartext; check anonymous access"),
    "smb": (Severity.MEDIUM, "SMB exposed to the network"),
    "microsoft-ds": (Severity.MEDIUM, "SMB exposed to the network"),
    "docker": (Severity.HIGH, "Docker API exposure can mean host takeover"),
    "snmp": (Severity.LOW, "SNMP may leak system info with default community"),
    "rabbitmq-mgmt": (Severity.LOW, "message-broker management interface exposed"),
}


@dataclass
class OpenPort:
    port: int
    service: str = "unknown"
    product: str = ""
    version: str = ""
    state: str = "open"

    @property
    def banner(self) -> str:
        return " ".join(p for p in (self.product, self.version) if p).strip()


@dataclass
class PortScanResult:
    host: str
    method: str  # "nmap" | "connect"
    open_ports: List[OpenPort] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "method": self.method,
            "open_ports": [
                {"port": p.port, "service": p.service, "banner": p.banner, "state": p.state}
                for p in self.open_ports
            ],
            "errors": self.errors,
        }

    def to_findings(self) -> List[Finding]:
        findings: List[Finding] = []
        for p in self.open_ports:
            sev, why = _SENSITIVE.get(p.service, (Severity.INFO, "service reachable"))
            banner = f" ({p.banner})" if p.banner else ""
            findings.append(
                Finding(
                    plugin="port-scan",
                    title=f"Open port {p.port}/tcp — {p.service}{banner}",
                    severity=sev,
                    description=(
                        f"Port {p.port} ({p.service}) is open and reachable: {why}. "
                        "Confirm the service is meant to be internet-facing and is "
                        "authenticated and patched."
                    ),
                    confidence=Confidence.FIRM if p.banner else Confidence.TENTATIVE,
                    cwe="CWE-668" if sev >= Severity.MEDIUM else None,
                    evidence=f"{self.host}:{p.port} open ({p.service}{' ' + p.banner if p.banner else ''})",
                    remediation=(
                        "Restrict exposure with a firewall/security group, require "
                        "authentication, and keep the service patched."
                    ),
                    url=f"tcp://{self.host}:{p.port}",
                    tags=["port-scan", "recon", p.service],
                    site_wide=True,
                )
            )
        return findings


class PortScanner:
    def __init__(
        self,
        scope: Scope,
        timeout: float = 1.5,
        concurrency: int = 100,
        use_nmap: bool = True,
    ) -> None:
        self.scope = scope
        self.timeout = timeout
        self.concurrency = concurrency
        self.use_nmap = use_nmap

    def nmap_available(self) -> bool:
        return self.use_nmap and shutil.which("nmap") is not None

    async def scan(self, host: str, ports: Optional[List[int]] = None) -> PortScanResult:
        host = self.scope.check_host(host)  # enforces allowlist + private policy
        ports = ports or DEFAULT_PORTS
        if self.nmap_available():
            try:
                return await self._scan_nmap(host, ports)
            except Exception as exc:  # noqa: BLE001 - fall back to connect scan
                result = await self._scan_connect(host, ports)
                result.errors.append(f"nmap failed, used connect scan: {exc}")
                return result
        return await self._scan_connect(host, ports)

    async def _scan_connect(self, host: str, ports: List[int]) -> PortScanResult:
        result = PortScanResult(host=host, method="connect")
        sem = asyncio.Semaphore(self.concurrency)

        async def probe(port: int) -> None:
            async with sem:
                try:
                    fut = asyncio.open_connection(host, port)
                    reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
                except (OSError, asyncio.TimeoutError):
                    return
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
                result.open_ports.append(
                    OpenPort(port=port, service=COMMON_PORTS.get(port, "unknown"))
                )

        await asyncio.gather(*(probe(p) for p in ports))
        result.open_ports.sort(key=lambda p: p.port)
        return result

    async def _scan_nmap(self, host: str, ports: List[int]) -> PortScanResult:
        port_arg = ",".join(str(p) for p in ports)
        # -Pn: don't ping; -sT: TCP connect (no root); -sV --version-light:
        # modest service detection; -T3: default timing (polite).
        cmd = [
            "nmap", "-Pn", "-sT", "-sV", "--version-light",
            "-T3", "-p", port_arg, "-oX", "-", host,
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError((stderr or b"").decode(errors="replace")[:200])
        return parse_nmap_xml(stdout.decode(errors="replace"), host)


def parse_nmap_xml(xml: str, host: str) -> PortScanResult:
    result = PortScanResult(host=host, method="nmap")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        result.errors.append(f"could not parse nmap output: {exc}")
        return result
    for port_el in root.iter("port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        svc = port_el.find("service")
        result.open_ports.append(
            OpenPort(
                port=int(port_el.get("portid", "0")),
                service=(svc.get("name") if svc is not None else None) or "unknown",
                product=(svc.get("product") if svc is not None else "") or "",
                version=(svc.get("version") if svc is not None else "") or "",
            )
        )
    result.open_ports.sort(key=lambda p: p.port)
    return result


def parse_ports(spec: str) -> List[int]:
    """Parse '22,80,443,8000-8010' into a sorted unique port list."""
    out: set = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            for p in range(int(lo), int(hi) + 1):
                if 0 < p < 65536:
                    out.add(p)
        else:
            p = int(part)
            if 0 < p < 65536:
                out.add(p)
    return sorted(out)
