# scripts/https/enum/banner_grab.py
import urllib.request, urllib.error, ssl
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

class Script(BaseScript):
    name        = "banner-grab"
    protocol    = "https"
    category    = "enum"
    description = "Obtiene headers del servidor HTTP, detecta tecnologías, versiones y WAF."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto HTTPS",
         "good": "https --script=banner-grab -t 10.10.10.5 --port 445",
         "bad":  "https --script=banner-grab (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        path    = kwargs.get("path") or "/"
        ip      = self.target.ip
        url     = f"https://{ip}:{port}{path}"

        try:
            req  = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Connection": "close",
            })
            resp = urllib.request.urlopen(req, timeout=timeout)
            status  = resp.status
            headers = dict(resp.headers)
            body    = resp.read(65536).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            status  = e.code
            headers = dict(e.headers) if e.headers else {}
            body    = ""
        except Exception as e:
            print_result("HTTPS", ip, "fail", f"error: {e}")
            return None

        interesting = [
            "server", "x-powered-by", "x-aspnet-version", "x-generator",
            "x-drupal-cache", "via", "x-varnish", "cf-ray",
            "x-amz-request-id", "x-backend-server",
        ]
        headers_lower = {k.lower(): v for k, v in headers.items()}
        rows = [(h, headers_lower[h]) for h in interesting if h in headers_lower]

        print_result("HTTPS", ip, "info", f"HTTPS {status} — {url}")
        if rows:
            print_table(f"Headers relevantes — {ip}:{port}", ["Header", "Valor"], rows)

        combined = " ".join(f"{k} {v}" for k, v in headers.items()).lower() + body.lower()
        techs = []
        for tech, sigs in [
            ("WordPress", ["wp-content","wp-includes"]),
            ("Joomla",    ["joomla","/components/com_"]),
            ("Drupal",    ["drupal","sites/default"]),
            ("PHP",       ["x-powered-by: php",".php"]),
            ("ASP.NET",   ["x-powered-by: asp","__viewstate"]),
            ("nginx",     ["nginx"]),
            ("Apache",    ["apache","httpd"]),
            ("IIS",       ["microsoft-iis"]),
            ("Cloudflare",["cf-ray","cloudflare"]),
        ]:
            if any(s.lower() in combined for s in sigs):
                techs.append(tech)

        if techs:
            print_result("HTTPS", ip, "info", f"Tecnologías: {', '.join(techs)}")
            session_db.save_finding(ip, "HTTPS", "technologies", ", ".join(techs))

        session_db.save_finding(ip, "HTTPS", "banner", f"HTTSP {status} port={port}")
        return {"status": status, "headers": headers, "technologies": techs}
