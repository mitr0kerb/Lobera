# scripts/http/enum/tech_detect.py
import urllib.request, urllib.error, re
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

TECH_DB = {
    "WordPress":     {"headers": [],                                    "body": ["wp-content/","wp-includes/","wp-json/"]},
    "Joomla":        {"headers": [],                                    "body": ["/components/com_","Joomla!"]},
    "Drupal":        {"headers": ["x-drupal-cache","x-generator: drupal"], "body": ["sites/default/files","drupal.js"]},
    "Laravel":       {"headers": ["set-cookie: laravel_session"],       "body": ["laravel_token","_token"]},
    "Django":        {"headers": [],                                    "body": ["csrfmiddlewaretoken","djdt-hidden"]},
    "Flask":         {"headers": [],                                    "body": ["werkzeug","flask"]},
    "Spring Boot":   {"headers": ["x-application-context"],            "body": ["spring","actuator"]},
    "ASP.NET MVC":   {"headers": ["x-aspnetmvc-version","x-powered-by: asp.net"], "body": ["__RequestVerificationToken"]},
    "ASP.NET":       {"headers": ["x-powered-by: asp.net","x-aspnet-version"], "body": ["__VIEWSTATE"]},
    "PHP":           {"headers": ["x-powered-by: php"],                "body": [".php?",".php\""]},
    "Ruby on Rails": {"headers": ["x-powered-by: phusion passenger"],  "body": ["rails","csrf-token"]},
    "Next.js":       {"headers": ["x-powered-by: next.js"],            "body": ["__NEXT_DATA__","/_next/static"]},
    "React":         {"headers": [],                                    "body": ["react.development.js","__react"]},
    "Vue.js":        {"headers": [],                                    "body": ["vue.min.js","__vue__"]},
    "Angular":       {"headers": [],                                    "body": ["ng-version=","angular.min.js"]},
    "jQuery":        {"headers": [],                                    "body": ["jquery.min.js","jQuery v"]},
    "nginx":         {"headers": ["server: nginx"],                     "body": []},
    "Apache":        {"headers": ["server: apache"],                    "body": []},
    "IIS":           {"headers": ["server: microsoft-iis"],             "body": []},
    "Tomcat":        {"headers": ["server: apache-coyote"],             "body": ["Apache Tomcat"]},
    "Cloudflare":    {"headers": ["cf-ray","server: cloudflare"],       "body": []},
    "Varnish":       {"headers": ["x-varnish","via: varnish"],         "body": []},
    "AWS CloudFront":{"headers": ["x-amz-cf-id"],                      "body": []},
}

class Script(BaseScript):
    name        = "tech-detect"
    protocol    = "http"
    category    = "enum"
    description = "Detecta tecnologías, frameworks, CMS, servidores y CDNs usados por la aplicación HTTP."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto",
         "good": "http --script=tech-detect -t 10.10.10.5 --port 80",
         "bad":  "http --script=tech-detect (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 80)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        ip      = self.target.ip
        url     = f"http://{ip}:{port}/"

        try:
            req  = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Connection": "close"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            body    = resp.read(512 * 1024).decode("utf-8", errors="replace").lower()
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v.lower() for k, v in e.headers.items()} if e.headers else {}
            body    = ""
        except Exception as e:
            print_result("HTTP", ip, "fail", f"error: {e}")
            return None

        found = {}
        headers_str = " ".join(f"{k}: {v}" for k, v in headers.items())
        for tech, sigs in TECH_DB.items():
            score = sum(2 for h in sigs["headers"] if h.lower() in headers_str)
            score += sum(1 for b in sigs["body"] if b.lower() in body)
            if score > 0:
                found[tech] = score

        if not found:
            print_result("HTTP", ip, "info", "No se detectaron tecnologías conocidas")
            return {}

        sorted_techs = sorted(found.items(), key=lambda x: x[1], reverse=True)
        rows = [(t, "Alta" if s >= 2 else "Media") for t, s in sorted_techs]
        print_table(f"Tecnologías — {ip}:{port}", ["Tecnología", "Confianza"], rows)

        tech_names = [t for t, _ in sorted_techs]
        session_db.save_finding(ip, "HTTP", "tech_detect", ", ".join(tech_names))

        waf_found = []
        for waf, sigs in [
            ("Cloudflare", ["cf-ray","server: cloudflare"]),
            ("Akamai",     ["akamai","ak_bmsc"]),
            ("Imperva",    ["incap_ses","visid_incap"]),
            ("AWS WAF",    ["x-amzn-waf"]),
        ]:
            if any(s.lower() in headers_str for s in sigs):
                waf_found.append(waf)

        if waf_found:
            print_result("HTTP", ip, "info", f"WAF detectado: {', '.join(waf_found)}")
            session_db.save_finding(ip, "HTTP", "waf_detected", ", ".join(waf_found))

        return {"technologies": tech_names, "waf": waf_found}
