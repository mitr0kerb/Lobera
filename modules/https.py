# modules/https.py

import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
import time

from core.output import print_result, print_table, print_check, console
from core import session_db

PROTO = "HTTPS"

TECH_SIGNATURES = {
    "WordPress":    ["wp-content", "wp-includes", "wordpress"],
    "Joomla":       ["joomla", "/components/com_"],
    "Drupal":       ["drupal", "sites/default/files"],
    "Laravel":      ["laravel_session"],
    "Django":       ["csrfmiddlewaretoken", "django"],
    "Flask":        ["werkzeug", "flask"],
    "Spring":       ["X-Application-Context", "spring"],
    "ASP.NET":      ["X-Powered-By: ASP.NET", "__VIEWSTATE"],
    "PHP":          ["X-Powered-By: PHP", ".php"],
    "nginx":        ["nginx"],
    "Apache":       ["Apache", "httpd"],
    "IIS":          ["Microsoft-IIS"],
    "Cloudflare":   ["cf-ray", "cloudflare"],
    "AWS":          ["x-amz-", "amazonaws"],
}

WAF_SIGNATURES = {
    "Cloudflare":  ["cf-ray", "__cfduid"],
    "Akamai":      ["akamai", "ak_bmsc"],
    "Imperva":     ["incap_ses", "visid_incap"],
    "F5 BIG-IP":   ["BIGipServer"],
    "ModSecurity": ["mod_security"],
    "AWS WAF":     ["x-amzn-waf"],
}

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options", "referrer-policy",
    "permissions-policy", "cross-origin-embedder-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy", "expect-ct",
]


class HTTPSModule:
    def __init__(self, target, creds=None):
        self.target  = target
        self.creds   = creds
        self._port   = 443
        self._scheme = "https"
        self._session_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode    = ssl.CERT_NONE

    def _proto(self): return PROTO

    def _base_url(self, port=None, path="/"):
        port = port or self._port
        return f"{self._scheme}://{self.target.ip}:{port}{path}"

    def _make_request(self, url, method="GET", headers=None, data=None,
                      timeout=None, allow_redirects=True):
        timeout = timeout or self.target.timeout or 5
        hdrs    = dict(self._session_headers)
        if headers:
            hdrs.update(headers)

        try:
            req = urllib.request.Request(url, headers=hdrs, method=method)
            if data:
                req.data = data.encode() if isinstance(data, str) else data

            handlers = [urllib.request.HTTPSHandler(context=self._ssl_ctx),
                        urllib.request.HTTPCookieProcessor()]
            if not allow_redirects:
                handlers.append(NoRedirectHandler())
            opener = urllib.request.build_opener(*handlers)

            resp = opener.open(req, timeout=timeout)
            body = resp.read(1024 * 1024)
            return {
                "status":  resp.status,
                "headers": dict(resp.headers),
                "body":    body.decode("utf-8", errors="replace"),
                "url":     resp.url,
            }
        except urllib.error.HTTPError as e:
            body = b""
            try: body = e.read(65536)
            except Exception: pass
            return {
                "status":  e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body":    body.decode("utf-8", errors="replace"),
                "url":     url,
            }
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}

    def connect(self, port=443, timeout=None):
        self._port = port
        url  = self._base_url(port)
        resp = self._make_request(url, timeout=timeout)
        if resp["status"] == 0:
            print_result(PROTO, self.target.ip, "fail",
                         f"no se pudo conectar a {url}: {resp.get('error','')}")
            return False
        print_result(PROTO, self.target.ip, "ok",
                     f"conectado a {url} — HTTP {resp['status']}")
        session_db.save_target(self.target.ip, domain=self.target.domain)
        return True

    def disconnect(self): pass

    def get(self, path="/", headers=None, timeout=None, allow_redirects=True):
        return self._make_request(self._base_url(path=path), headers=headers,
                                  timeout=timeout, allow_redirects=allow_redirects)

    def post(self, path="/", data=None, headers=None, timeout=None):
        return self._make_request(self._base_url(path=path), method="POST",
                                  data=data, headers=headers, timeout=timeout)

    def detect_technologies(self, resp):
        found    = []
        combined = (" ".join(f"{k}: {v}" for k, v in resp.get("headers",{}).items())
                    + " " + resp.get("body","")).lower()
        for tech, sigs in TECH_SIGNATURES.items():
            if any(s.lower() in combined for s in sigs):
                found.append(tech)
        return found

    def detect_waf(self, resp):
        found    = []
        combined = (" ".join(f"{k}: {v}" for k, v in resp.get("headers",{}).items())
                    + " " + resp.get("body","")).lower()
        for waf, sigs in WAF_SIGNATURES.items():
            if any(s.lower() in combined for s in sigs):
                found.append(waf)
        return found

    def get_security_headers(self, resp):
        present = {}
        missing = []
        headers_lower = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        for h in SECURITY_HEADERS:
            if h in headers_lower:
                present[h] = headers_lower[h]
            else:
                missing.append(h)
        return present, missing


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None
    def http_error_301(self, req, fp, code, msg, headers): return None
    def http_error_302(self, req, fp, code, msg, headers): return None
    def http_error_303(self, req, fp, code, msg, headers): return None
    def http_error_307(self, req, fp, code, msg, headers): return None
    def http_error_308(self, req, fp, code, msg, headers): return None
