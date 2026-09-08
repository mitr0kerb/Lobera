# scripts/https/enum/tech_detect.py
import ssl, urllib.request, urllib.error
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

TECH_DB = {
    "WordPress":     {"headers": [],                                        "body": ["wp-content/","wp-includes/","wp-json/"]},
    "Joomla":        {"headers": [],                                        "body": ["/components/com_","Joomla!"]},
    "Drupal":        {"headers": ["x-drupal-cache","x-generator: drupal"], "body": ["sites/default/files","drupal.js"]},
    "Laravel":       {"headers": ["set-cookie: laravel_session"],           "body": ["laravel_token","_token"]},
    "Django":        {"headers": [],                                        "body": ["csrfmiddlewaretoken"]},
    "Flask":         {"headers": [],                                        "body": ["werkzeug","flask"]},
    "Spring Boot":   {"headers": ["x-application-context"],                "body": ["spring","actuator"]},
    "ASP.NET":       {"headers": ["x-powered-by: asp.net","x-aspnet-version"], "body": ["__VIEWSTATE"]},
    "PHP":           {"headers": ["x-powered-by: php"],                    "body": [".php?"]},
    "Ruby on Rails": {"headers": ["x-powered-by: phusion passenger"],      "body": ["rails","csrf-token"]},
    "Next.js":       {"headers": ["x-powered-by: next.js"],                "body": ["__NEXT_DATA__","/_next/static"]},
    "React":         {"headers": [],                                        "body": ["react.development.js","__react"]},
    "Vue.js":        {"headers": [],                                        "body": ["vue.min.js","__vue__"]},
    "Angular":       {"headers": [],                                        "body": ["ng-version="]},
    "nginx":         {"headers": ["server: nginx"],                         "body": []},
    "Apache":        {"headers": ["server: apache"],                        "body": []},
    "IIS":           {"headers": ["server: microsoft-iis"],                 "body": []},
    "Cloudflare":    {"headers": ["cf-ray","server: cloudflare"],           "body": []},
    "AWS CloudFront":{"headers": ["x-amz-cf-id"],                          "body": []},
}

class Script(BaseScript):
    name        = "tech-detect"
    protocol    = "https"
    category    = "enum"
    description = "Detecta tecnologías, frameworks, CMS, servidores y CDNs sobre HTTPS."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto",
         "good": "https --script=tech-detect -t 10.10.10.5 --port 443",
         "bad":  "https --script=tech-detect (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip
        url     = f"https://{ip}:{port}/"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        try:
            req    = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0","Connection":"close"})
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            try:
                resp    = opener.open(req, timeout=timeout)
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                body    = resp.read(512*1024).decode("utf-8", errors="replace").lower()
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v.lower() for k, v in e.headers.items()} if e.headers else {}
                body    = ""
        except Exception as e:
            print_result("HTTPS", ip, "fail", f"error: {e}")
            return None

        found = {}
        headers_str = " ".join(f"{k}: {v}" for k, v in headers.items())
        for tech, sigs in TECH_DB.items():
            score  = sum(2 for h in sigs["headers"] if h.lower() in headers_str)
            score += sum(1 for b in sigs["body"] if b.lower() in body)
            if score > 0:
                found[tech] = score

        if not found:
            print_result("HTTPS", ip, "info", "No se detectaron tecnologías conocidas")
            return {}

        sorted_techs = sorted(found.items(), key=lambda x: x[1], reverse=True)
        rows = [(t, "Alta" if s >= 2 else "Media") for t, s in sorted_techs]
        print_table(f"Tecnologías HTTPS — {ip}:{port}", ["Tecnología","Confianza"], rows)

        tech_names = [t for t, _ in sorted_techs]
        session_db.save_finding(ip, "HTTPS", "tech_detect", ", ".join(tech_names))

        waf_found = []
        for waf, sigs in [
            ("Cloudflare", ["cf-ray","server: cloudflare"]),
            ("Akamai",     ["akamai","ak_bmsc"]),
            ("AWS WAF",    ["x-amzn-waf"]),
        ]:
            if any(s.lower() in headers_str for s in sigs):
                waf_found.append(waf)
        if waf_found:
            print_result("HTTPS", ip, "info", f"WAF: {', '.join(waf_found)}")
            session_db.save_finding(ip, "HTTPS", "waf_detected", ", ".join(waf_found))

        return {"technologies": tech_names, "waf": waf_found}
