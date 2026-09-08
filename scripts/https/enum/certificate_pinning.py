# scripts/https/enum/certificate_pinning.py
import ssl, socket, hashlib, base64, urllib.request, urllib.error
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "certificate-pinning"
    protocol    = "https"
    category    = "enum"
    description = "Script propio: detecta HPKP, Expect-CT y calcula SPKI hash del certificado actual."

    EXAMPLES = [
        {"flag": "-t / --port", "desc": "IP y puerto HTTPS",
         "good": "https --script=certificate-pinning -t 10.10.10.5 --port 443",
         "bad":  "https --script=certificate-pinning (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        sni     = kwargs.get("sni") or self.target.ip
        ip      = self.target.ip

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        cert_der = None
        headers  = {}

        try:
            raw  = socket.create_connection((ip, port), timeout=timeout)
            conn = ctx.wrap_socket(raw, server_hostname=sni)
            cert_der = conn.getpeercert(binary_form=True)
            conn.close()
        except Exception as e:
            print_result("HTTPS", ip, "fail", f"error cert: {e}")

        try:
            url    = f"https://{ip}:{port}/"
            req    = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            try:
                resp    = opener.open(req, timeout=timeout)
                headers = {k.lower(): v for k, v in resp.headers.items()}
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        except Exception:
            pass

        hpkp      = headers.get("public-key-pins","")
        expect_ct = headers.get("expect-ct","")

        spki_hash = ""
        if cert_der:
            spki_hash = "sha256//" + base64.b64encode(
                hashlib.sha256(cert_der).digest()).decode()
            session_db.save_finding(ip, "HTTPS", "cert_spki_hash", spki_hash)

        has_pinning = bool(hpkp or expect_ct)
        rows = [
            ("HPKP",          hpkp[:50] if hpkp else "no presente"),
            ("Expect-CT",     expect_ct[:50] if expect_ct else "no presente"),
            ("SPKI calculado", spki_hash[:50] if spki_hash else "—"),
            ("Pinning activo", "Sí" if has_pinning else "No detectado"),
        ]
        print_table(f"Certificate Pinning — {ip}:{port}", ["Check","Valor"], rows)

        if not has_pinning:
            print_result("HTTPS", ip, "info", "Sin certificate pinning — cert alternativo posible en MitM")
        else:
            print_check("Certificate pinning presente", ok=True)

        return {"hpkp": hpkp, "expect_ct": expect_ct, "has_pinning": has_pinning}
