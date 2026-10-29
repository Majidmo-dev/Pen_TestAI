"""Raw tool output -> typed JSON. Parsers never raise: bad input yields an 'error' key."""
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

MAX_LINKS = 100
MAX_FORMS = 20


def parse_nmap_xml(xml: str) -> dict:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        return {"error": f"unparseable nmap XML: {e}", "hosts": []}

    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        addr = h.find("address")
        ports = []
        for p in h.findall("ports/port"):
            state = p.find("state")
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "state": state.get("state") if state is not None else None,
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
            })
        hosts.append({
            "address": addr.get("addr") if addr is not None else None,
            "status": status.get("state") if status is not None else None,
            "hostnames": [n.get("name") for n in h.findall("hostnames/hostname")],
            "ports": ports,
        })
    return {"hosts": hosts}


class _PageParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.title = None
        self._in_title = False
        self.links = []
        self.forms = []
        self._form = None

    def _url(self, ref):
        if not ref or ref.startswith(("javascript:", "mailto:", "data:", "#")):
            return None
        return urljoin(self.base, ref.strip())

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag in ("a", "link") and a.get("href"):
            u = self._url(a["href"])
            if u and len(self.links) < MAX_LINKS:
                self.links.append(u)
        elif tag in ("script", "img", "iframe", "frame") and a.get("src"):
            u = self._url(a["src"])
            if u and len(self.links) < MAX_LINKS:
                self.links.append(u)
        elif tag == "form" and len(self.forms) < MAX_FORMS:
            self._form = {"action": self._url(a.get("action") or "") or self.base,
                          "method": (a.get("method") or "GET").upper(),
                          "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            if a.get("name"):
                self._form["inputs"].append({"name": a["name"],
                                             "type": a.get("type", tag)})

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title and self.title is None and data.strip():
            self.title = data.strip()[:200]


def parse_curl_response(output: str, url: str) -> dict:
    """Parse `curl -i` output (status line + headers + body)."""
    text = output.replace("\r\n", "\n")
    head, sep, body = text.partition("\n\n")
    if not sep:
        return {"url": url, "error": "no HTTP response parsed", "raw_head": text[:500]}

    lines = head.split("\n")
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        return {"url": url, "error": f"bad status line: {status_line[:200]}"}

    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        if k.strip():
            headers.setdefault(k.strip().lower(), v.strip())

    result = {
        "url": url,
        "status": status,
        "server": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
        "content_type": headers.get("content-type"),
        "set_cookie": [l.split(":", 1)[1].strip().split(";")[0].split("=")[0]
                       for l in lines[1:] if l.lower().startswith("set-cookie:")],
        "body_bytes": len(body.encode()),
    }
    if "location" in headers:
        result["redirect"] = urljoin(url, headers["location"])

    if "html" in (headers.get("content-type") or "html"):
        pp = _PageParser(url)
        try:
            pp.feed(body)
            pp.close()
        except Exception as e:  # malformed HTML from the target must not crash the agent
            result["html_error"] = str(e)[:200]
        result["title"] = pp.title
        host = urlsplit(url).hostname
        # Same-host links only: off-host links are noise and invite scope drift.
        result["links"] = sorted({u for u in pp.links if urlsplit(u).hostname == host})
        result["offhost_links"] = len({u for u in pp.links if urlsplit(u).hostname != host})
        result["forms"] = pp.forms
    return result
