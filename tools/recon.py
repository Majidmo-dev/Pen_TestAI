import ipaddress, re
from urllib.parse import quote

from tools.base import Tool, Target, ScopeError
from tools.parsers import parse_nmap_xml, parse_curl_response


def _expand_ports(spec: str) -> list:
    if not re.fullmatch(r"\d+(-\d+)?(,\d+(-\d+)?)*", spec):
        raise ValueError(f"bad port spec {spec!r}; use e.g. '80,443,8000-8100'")
    out = []
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        lo, hi = int(lo), int(hi or lo)
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(f"port out of range: {part}")
        out.append((lo, hi))
    return out


def _host_for_url(host: str) -> str:
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"
    except ValueError:
        pass
    return host


class NmapScan(Tool):
    name = "nmap"
    description = ("TCP connect scan with service/version detection on one host. "
                   "Target is a hostname or IP, not a URL path or CIDR range.")
    timeout = 300
    args = {"ports": {"type": "str",
                      "description": "Ports to scan, e.g. '80,443' or '1-1024'. "
                                     "Defaults to every in-scope port."}}

    def build(self, target: Target, args: dict, scope) -> list:
        if "ports" in args:
            ranges = _expand_ports(args["ports"])
            bad = [f"{lo}-{hi}" if lo != hi else str(lo) for lo, hi in ranges
                   if not all(scope.port_allowed(p) for p in range(lo, hi + 1))]
            if bad:
                raise ScopeError(f"ports out of scope: {','.join(bad)}")
            ports = args["ports"]
        else:
            ports = scope.port_spec()
        # -sT: connect scan works without root/raw sockets (container drops all caps).
        return ["nmap", "-sT", "-sV", "-Pn", "--unprivileged", "-T3",
                "--max-retries", "2", "--host-timeout", "240s",
                "-p", ports, "-oX", "-", target.host]

    def parse(self, stdout, target, cmd):
        return parse_nmap_xml(stdout)


class WebProbe(Tool):
    name = "webprobe"
    description = ("Single HTTP GET/HEAD request (no redirects followed). Returns status, "
                   "headers, title, same-host links and forms. Target is a URL or host.")
    timeout = 30
    args = {"path": {"type": "str",
                     "description": "Path and optional query, e.g. '/login.php'. "
                                    "Overrides any path in the target URL."},
            "method": {"type": "str", "choices": ["GET", "HEAD"],
                       "description": "HTTP method (default GET)."}}

    def url_for(self, target: Target, args: dict, scope) -> str:
        scheme = target.scheme or "http"
        port = target.port or (443 if scheme == "https" else 80)
        if not scope.port_allowed(port):
            raise ScopeError(f"port {port} out of scope")
        path = args.get("path", target.path) or "/"
        if not path.startswith("/"):
            raise ValueError("path must start with '/'")
        # Encode anything unusual (spaces, control chars, '#') so curl sees one URL.
        path = quote(path, safe="/?&=%:;,+-._~!$'()*@")
        default = 443 if scheme == "https" else 80
        netloc = _host_for_url(target.host) + ("" if port == default else f":{port}")
        return f"{scheme}://{netloc}{path}"

    def build(self, target: Target, args: dict, scope) -> list:
        url = self.url_for(target, args, scope)
        cmd = ["curl", "-sS", "-i", "--globoff", "--noproxy", "*",
               "--proto", "=http,https", "--max-redirs", "0",
               "--connect-timeout", "10", "-m", "20", "--max-filesize", "5000000",
               "-A", "pentest-agent/0.1"]
        if args.get("method") == "HEAD":
            cmd.append("-I")
        return cmd + [url]

    def parse(self, stdout, target, cmd):
        return parse_curl_response(stdout, cmd[-1])
