"""Port scanner: parsing, connect scan, scope, findings."""

from __future__ import annotations

import asyncio
import socket

import pytest

from panoptes.portscan import (
    OpenPort,
    PortScanner,
    PortScanResult,
    parse_nmap_xml,
    parse_ports,
)
from panoptes.scope import OutOfScopeError, Scope

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_parse_ports():
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    assert parse_ports("443,443,80") == [80, 443]  # dedupe + sort


def test_parse_nmap_xml():
    res = parse_nmap_xml(_NMAP_XML, "127.0.0.1")
    ports = {p.port for p in res.open_ports}
    assert ports == {22, 80}  # closed port excluded
    ssh = next(p for p in res.open_ports if p.port == 22)
    assert ssh.service == "ssh"
    assert ssh.banner == "OpenSSH 8.2p1"


def test_parse_nmap_xml_garbage():
    res = parse_nmap_xml("not xml", "h")
    assert res.open_ports == []
    assert res.errors


def test_to_findings_marks_sensitive_services():
    res = PortScanResult(host="h", method="connect",
                         open_ports=[OpenPort(port=6379, service="redis")])
    findings = res.to_findings()
    assert len(findings) == 1
    assert findings[0].severity.name == "HIGH"
    assert findings[0].plugin == "port-scan"


def test_connect_scan_detects_open_port():
    # Open a real listening socket on an ephemeral port.
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    open_port = lsock.getsockname()[1]

    # Reserve then release a port to get one that is (almost certainly) closed.
    csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    csock.bind(("127.0.0.1", 0))
    closed_port = csock.getsockname()[1]
    csock.close()

    scope = Scope(allow=["127.0.0.1"], allow_private=True, authorized=True)
    scanner = PortScanner(scope, timeout=1.0, use_nmap=False)
    try:
        result = asyncio.run(scanner.scan("127.0.0.1", [open_port, closed_port]))
    finally:
        lsock.close()

    found = {p.port for p in result.open_ports}
    assert open_port in found
    assert closed_port not in found
    assert result.method == "connect"


def test_scan_enforces_scope():
    scope = Scope(allow=["example.com"], authorized=True)
    scanner = PortScanner(scope, use_nmap=False)
    with pytest.raises(OutOfScopeError):
        asyncio.run(scanner.scan("127.0.0.1", [80]))
