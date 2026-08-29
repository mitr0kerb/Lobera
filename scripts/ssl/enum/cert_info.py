# scripts/ssl/enum/cert_info.py
import ssl, socket, hashlib, base64, datetime
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

class Script(BaseScript):
    name        = "cert-info"
    protocol    = "ssl"
    category    = "enum"
    description = "Extrae información completa del certificado SSL/TLS: CN, SAN, emisor, expiración, algoritmo y huella."

    EXAMPLES = [
        {"flag": "-t / --port",
         "desc": "IP y puerto SSL (default: 443)",
         "good": "ssl --script=cert-info -t 10.10.10.5 --port 443",
         "bad":  "ssl --script=cert-info (sin -t)"},
    ]

    def run(self, **kwargs):
        port    = int(kwargs.get("port") or 443)
        timeout = int(kwargs.get("timeout") or self.target.timeout or 5)
        sni     = kwargs.get("sni") or self.target.ip
        ip      = self.target.ip

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw  = socket.create_connection((ip, port), timeout=timeout)
            conn = ctx.wrap_socket(raw, server_hostname=sni)
            cert_dict = conn.getpeercert()
            cert_der  = conn.getpeercert(binary_form=True)
            tls_ver   = conn.version()
            cipher    = conn.cipher()
            conn.close()
        except Exception as e:
            print_result("SSL", ip, "fail", f"no se pudo obtener certificado: {e}")
            return None

        if not cert_dict:
            print_result("SSL", ip, "fail", "servidor no presentó certificado")
            return None

        subject    = dict(x[0] for x in cert_dict.get("subject", []))
        issuer     = dict(x[0] for x in cert_dict.get("issuer", []))
        san_list   = [v for t, v in cert_dict.get("subjectAltName", [])]
        not_before = cert_dict.get("notBefore", "")
        not_after  = cert_dict.get("notAfter",  "")

        try:
            exp_date  = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.datetime.utcnow()).days
            exp_str   = f"{not_after} ({days_left} días restantes)"
            expires_soon = days_left < 30
        except Exception:
            exp_str = not_after
            expires_soon = False
            days_left = -1

        sha1_fp    = hashlib.sha1(cert_der).hexdigest().upper()
        sha256_fp  = hashlib.sha256(cert_der).hexdigest().upper()
        sha1_fmt   = ":".join(sha1_fp[i:i+2]   for i in range(0, len(sha1_fp),   2))
        sha256_fmt = ":".join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2))

        rows = [
            ("CN (Common Name)",   subject.get("commonName",       "?")),
            ("Organización",       subject.get("organizationName", "?")),
            ("Emisor CN",          issuer.get("commonName",        "?")),
            ("Emisor Org",         issuer.get("organizationName",  "?")),
            ("Válido desde",       not_before),
            ("Expira",             exp_str),
            ("SANs",               ", ".join(san_list) if san_list else "ninguno"),
            ("TLS negociado",      tls_ver or "?"),
            ("Cipher suite",       cipher[0] if cipher else "?"),
            ("SHA1 fingerprint",   sha1_fmt),
            ("SHA256 fingerprint", sha256_fmt),
        ]
        print_table(f"Certificado SSL — {ip}:{port}", ["Campo", "Valor"], rows)

        if expires_soon:
            print_result("SSL", ip, "fail",
                         f"CERTIFICADO EXPIRA EN {days_left} DÍAS")
            session_db.save_finding(ip, "SSL", "cert_expiring_soon", f"{days_left} días")
        if days_left < 0:
            print_result("SSL", ip, "pwned", "CERTIFICADO EXPIRADO")
            session_db.save_finding(ip, "SSL", "cert_expired", not_after)

        if subject.get("commonName") == issuer.get("commonName"):
            print_check("Certificado auto-firmado (self-signed)", ok=False)
            session_db.save_finding(ip, "SSL", "self_signed_cert",
                                    subject.get("commonName","?"))

        session_db.save_finding(ip, "SSL", "cert_cn",  subject.get("commonName","?"))
        session_db.save_finding(ip, "SSL", "cert_san", ", ".join(san_list))

        return {
            "subject": subject, "issuer": issuer, "san": san_list,
            "not_after": not_after, "days_left": days_left,
            "sha256": sha256_fmt, "tls_version": tls_ver,
        }
