import ipaddress, re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


class ScopeConfigError(ValueError):
    pass


def split_target(raw):
    """Parse a planner target into (scheme, host, port, path_and_query), or None.

    The host is what a tool will actually contact (userinfo stripped, lowercased).
    Bare targets containing '/' (e.g. CIDR ranges like 'dvwa/0') are rejected:
    checking only the part before the slash would let a range escape scope.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    raw = raw.strip()
    if "://" not in raw:
        if "/" in raw:
            return None
        raw = "//" + raw
    try:
        parts = urlsplit(raw)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not host or (parts.scheme and parts.scheme not in ("http", "https")):
        return None
    path = parts.path or ""
    if parts.query:
        path += "?" + parts.query
    return parts.scheme, host, port, path


def target_host(raw):
    t = split_target(raw)
    return t[1] if t else None


def _parse_ports(entries) -> list:
    ranges = []
    for e in entries:
        if isinstance(e, bool):
            raise ScopeConfigError(f"invalid port entry: {e!r}")
        if isinstance(e, int):
            lo = hi = e
        elif isinstance(e, str) and re.fullmatch(r"\d+-\d+", e.strip()):
            lo, hi = (int(x) for x in e.strip().split("-"))
        elif isinstance(e, str) and e.strip().isdigit():
            lo = hi = int(e)
        else:
            raise ScopeConfigError(f"invalid port entry: {e!r}")
        if not (1 <= lo <= hi <= 65535):
            raise ScopeConfigError(f"port out of range: {e!r}")
        ranges.append((lo, hi))
    return sorted(ranges)


def _parse_domains(entries) -> list:
    out = []
    for d in entries:
        if not isinstance(d, str):
            raise ScopeConfigError(f"invalid domain: {d!r}")
        d = d.strip().lower().rstrip(".")
        bare = d[2:] if d.startswith("*.") else d
        if not _HOSTNAME_RE.match(bare):
            raise ScopeConfigError(f"invalid domain: {d!r}")
        out.append(d)
    return out


def _parse_cidrs(entries) -> list:
    try:
        return [ipaddress.ip_network(str(c).strip(), strict=False) for c in entries]
    except ValueError as e:
        raise ScopeConfigError(f"invalid CIDR: {e}") from None


class Scope:
    """Per-engagement allowlist. Loaded and validated eagerly; fails closed."""

    def __init__(self, path: str):
        p = Path(path)
        if not p.is_file():
            raise ScopeConfigError(f"scope file not found: {path}")
        cfg = yaml.safe_load(p.read_text()) or {}
        if not isinstance(cfg, dict):
            raise ScopeConfigError("scope file must be a mapping")

        targets = cfg.get("targets") or {}
        exclude = cfg.get("exclude") or {}
        self.engagement = cfg.get("engagement", "unnamed")
        self.domains = _parse_domains(targets.get("domains") or [])
        self.cidrs = _parse_cidrs(targets.get("cidrs") or [])
        self.excluded_domains = _parse_domains(exclude.get("domains") or [])
        self.excluded_cidrs = _parse_cidrs(exclude.get("cidrs") or [])
        self.ports = _parse_ports(cfg.get("ports") or [])

        if not self.domains and not self.cidrs:
            raise ScopeConfigError("scope has no targets (targets.domains / targets.cidrs)")
        if not self.ports:
            raise ScopeConfigError("scope has no ports; list them explicitly")

    @staticmethod
    def _domain_match(host: str, patterns: list) -> bool:
        for d in patterns:
            if d.startswith("*."):
                if host.endswith(d[1:]):  # subdomains only, not the apex
                    return True
            elif host == d:
                return True
        return False

    def is_allowed(self, host) -> bool:
        if not isinstance(host, str) or not host:
            return False
        host = host.strip().lower().rstrip(".")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None

        if ip is not None:
            if any(ip in n for n in self.excluded_cidrs if n.version == ip.version):
                return False
            return any(ip in n for n in self.cidrs if n.version == ip.version)

        # Hostnames are matched by name only; numeric forms like '2130706433'
        # fail the hostname check and are denied.
        if not _HOSTNAME_RE.match(host):
            return False
        if self._domain_match(host, self.excluded_domains):
            return False
        return self._domain_match(host, self.domains)

    def port_allowed(self, port: int) -> bool:
        return any(lo <= port <= hi for lo, hi in self.ports)

    def port_spec(self) -> str:
        """Allowed ports in nmap -p syntax, e.g. '80,443,8000-8100'."""
        return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in self.ports)
