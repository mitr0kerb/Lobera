# scripts/https/enum/dir_bruteforce.py
import ssl, urllib.request, urllib.error, time
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

DEFAULT_WORDLIST = [
    "admin","administrator","login","dashboard","panel","api","backup",
    "config","secret","private","uploads","files","images","static",
    "assets","css","js","old","test","dev","staging","beta",
    "wp-admin","wp-content","phpmyadmin","cpanel","webmail",
    ".git",".env",".htaccess","robots.txt","sitemap.xml","readme.txt",
    "web.config","composer.json","server-status","health",
    "info.php","phpinfo.php","manager","console","monitor",
]

class Script(BaseScript):
    name        = "dir-bruteforce"
    protocol    = "https"
    category    = "enum"
    description = "Fuerza bruta de directorios y ficheros sobre HTTPS."

    EXAMPLES = [
        {"flag": "--wordlist", "desc": "Wordlist de rutas",
         "good": "https --script=dir-bruteforce -t 10.10.10.5 --wordlist /opt/wordlists/common.txt",
         "bad":  "https --script=dir-bruteforce --delay 0 (puede disparar WAF)"},
    ]

    def run(self, **kwargs):
        port     = int(kwargs.get("port") or 443)
        timeout  = int(kwargs.get("timeout") or self.target.timeout or 5)
        wordlist = kwargs.get("wordlist")
        delay    = float(kwargs.get("delay") or 0)
        ext      = kwargs.get("extensions") or ""
        ip       = self.target.ip
        base     = f"https://{ip}:{port}"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

        paths = list(DEFAULT_WORDLIST)
        if wordlist:
            try:
                with open(wordlist) as f:
                    paths = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            except OSError as e:
                console.print(f"[red]No se pudo leer wordlist: {e}[/red]")
                return None

        extensions = [e.strip() for e in ext.split(",") if e.strip()] if ext else []
        if extensions:
            extra = [f"{p}.{e.lstrip('.')}" for p in paths if "." not in p for e in extensions]
            paths += extra

        print_result("HTTPS", ip, "info", f"dir-bruteforce HTTPS: {len(paths)} rutas")
        found = []

        for path in paths:
            url = f"{base}/{path.lstrip('/')}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0","Connection":"close"})
                try:
                    resp   = opener.open(req, timeout=timeout)
                    status = resp.status
                    size   = len(resp.read(65536))
                except urllib.error.HTTPError as e:
                    status = e.code
                    size   = 0

                if status not in (404, 400):
                    found.append((f"/{path}", str(status), str(size)))
                    if status == 200:
                        print_result("HTTPS", ip, "pwned", f"[{status}] {url}")
                        session_db.save_finding(ip, "HTTPS", "dir_found", url)
                    elif status == 403:
                        print_result("HTTPS", ip, "info", f"[{status}] {url} (forbidden)")
                        session_db.save_finding(ip, "HTTPS", "dir_forbidden", url)
            except Exception:
                pass
            if delay:
                time.sleep(delay)

        if found:
            print_table(f"Rutas HTTPS — {ip}:{port}", ["Ruta","Código","Tamaño"], found)
            print_result("HTTPS", ip, "pwned", f"{len(found)} ruta(s) encontrada(s)")
        else:
            print_result("HTTPS", ip, "info", "dir-bruteforce: sin resultados")

        return found
