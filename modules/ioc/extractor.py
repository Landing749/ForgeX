"""IOC Module.

Extracts Indicators of Compromise from arbitrary text/binary-as-text
content: IPs, domains, URLs, hashes, emails, CVEs, JWTs.

Fully self-contained (stdlib `re` only) so it works against any
artifact text produced by other modules (browser history, EVTX
messages, strings output, network logs, etc.) without extra
dependencies.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_IPV4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
_IPV6 = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b')
_DOMAIN = re.compile(
    r'\b(?=[a-z0-9-]{1,63}\.)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+'
    r'(?:com|net|org|io|co|info|biz|xyz|ru|cn|top|club|online|site|link|icu|shop|app|dev)\b',
    re.IGNORECASE,
)
_URL = re.compile(r'\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"\'<>]+')
_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
_JWT = re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b')

# Registries reserved / non-routable ranges we skip so scan results aren't
# dominated by noise like 127.0.0.1, 0.0.0.0, RFC1918 space, etc.
_PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "0.", "255.")


def _is_private_ipv4(ip: str) -> bool:
    if ip.startswith(_PRIVATE_PREFIXES):
        return True
    if ip.startswith("172."):
        second = int(ip.split(".")[1])
        return 16 <= second <= 31
    return False


@dataclass
class IOCResult:
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    md5: list[str] = field(default_factory=list)
    sha1: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    jwts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def total(self) -> int:
        return sum(len(v) for v in self.to_dict().values())


def extract_iocs(text: str, include_private_ips: bool = False) -> IOCResult:
    ipv4 = sorted(set(_IPV4.findall(text)))
    if not include_private_ips:
        ipv4 = [ip for ip in ipv4 if not _is_private_ipv4(ip)]

    return IOCResult(
        ipv4=ipv4,
        ipv6=sorted(set(_IPV6.findall(text))),
        domains=sorted(set(m.rstrip('.') for m in _DOMAIN.findall(text))),
        urls=sorted(set(_URL.findall(text))),
        emails=sorted(set(_EMAIL.findall(text))),
        # Longest-hash-first so a sha256 substring isn't double counted as md5/sha1
        sha256=sorted(set(_SHA256.findall(text))),
        sha1=sorted(set(_SHA1.findall(text))),
        md5=sorted(set(_MD5.findall(text))),
        cves=sorted(set(m.upper() for m in _CVE.findall(text))),
        jwts=sorted(set(_JWT.findall(text))),
    )


def extract_iocs_from_file(path: str | Path, encoding: str = "utf-8",
                            errors: str = "ignore") -> IOCResult:
    text = Path(path).read_text(encoding=encoding, errors=errors)
    return extract_iocs(text)
