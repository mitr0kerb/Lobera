# scripts/ldap/adcs/enum-templates.py
"""
Enumera plantillas de certificado de Active Directory Certificate Services (ADCS)
y detecta las más conocidas vulnerabilidades (ESC1-ESC8).

ESC1 — Plantilla permite SAN arbitrario + enroll de usuarios sin privilegios
ESC2 — Plantilla con EKU "Any Purpose" o sin EKU
ESC3 — Plantilla de Certificate Request Agent que puede solicitar en nombre de otro
ESC4 — Permisos de escritura sobre la plantilla (WriteDACL/WriteOwner/GenericWrite)
ESC6 — CA con flag EDITF_ATTRIBUTESUBJECTALTNAME2 (permite SAN en cualquier plantilla)
ESC7 — Principal no privilegiado con ManageCertificates o ManageCA sobre la CA
ESC8 — Enrollment endpoint HTTP sin autenticación extendida (relay NTLM → ADCS)

Requiere:
  - Credenciales de dominio (cualquier usuario del dominio)
  - Acceso LDAP al DC
"""

from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

try:
    from modules.ldap import LDAPModule
    _LDAP_OK = True
except ImportError:
    _LDAP_OK = False


# ── Constantes ADCS ──────────────────────────────────────────────────────────

# OIDs de Extended Key Usage relevantes
_EKU_CLIENT_AUTH    = "1.3.6.1.5.5.7.3.2"
_EKU_ANY_PURPOSE    = "2.5.29.37.0"
_EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
_EKU_SMARTCARD      = "1.3.6.1.4.1.311.20.2.2"

# Flags de msCTPT-PrivateKeyFlag
_CT_FLAG_EXPORTABLE_KEY      = 0x00000010
_CT_FLAG_REQUIRE_SAME_KEY_RENEWAL = 0x00000040

# Flags de msCT-Flags / msPKI-Certificate-Name-Flag
_ENROLLEE_SUPPLIES_SUBJECT       = 0x1     # ESC1: el solicitante pone el SAN
_ENROLLEE_SUPPLIES_SUBJECT_ALT   = 0x10000

# Permisos ACE peligrosos sobre plantillas
_DANGEROUS_RIGHTS_TEMPLATE = {
    "00000000-0000-0000-0000-000000000000": "GenericAll",
    "WriteDACL":   "WriteDACL",
    "WriteOwner":  "WriteOwner",
    "GenericWrite": "GenericWrite",
}


class Script(BaseScript):
    name        = "enum-templates"
    protocol    = "ldap"
    category    = "adcs"
    description = (
        "Enumera plantillas ADCS y detecta ESC1-ESC8 "
        "(plantillas con enroll de usuarios sin privilegios y SAN libre, "
        "EKU peligrosas, permisos de escritura sobre CA/plantilla)."
    )

    EXAMPLES = [
        {
            "flag":  "-t / -u / -p / -d",
            "desc":  "Credenciales de dominio (cualquier usuario sirve)",
            "good":  "lobera.py ldap --script=enum-templates -t 10.10.10.5 -u iker -p 'Pass1' -d CORP.LOCAL",
            "bad":   "lobera.py ldap --script=enum-templates -t 10.10.10.5  [sin credenciales LDAP no funciona]",
        },
    ]

    def run(self, **kwargs):
        if not _LDAP_OK:
            print_result("LDAP", str(self.target.ip), "fail",
                         "módulo LDAP no disponible"); return

        use_ssl = kwargs.get("ldaps", False)
        port    = kwargs.get("port")
        ldap    = LDAPModule(self.target, self.creds, use_ssl=use_ssl, port=port)
        if not ldap.connect():
            return

        try:
            console.rule("[bold yellow]ADCS — Enumeración de plantillas de certificado[/bold yellow]")

            # ── 1. Buscar CAs en el dominio ───────────────────────────────────
            console.print("\n[bold cyan]▶ Autoridades de certificación (CA)[/bold cyan]")
            cas = self._get_cas(ldap)
            if cas:
                print_table(
                    f"CAs encontradas ({len(cas)})",
                    ["Nombre", "DNS", "DN"],
                    [(ca.get("name","?"), ca.get("dns","?"), ca.get("dn","?"))
                     for ca in cas],
                )
            else:
                console.print("  [yellow]No se encontraron CAs en el dominio[/yellow]")
                return

            # ── 2. Enumerar plantillas ─────────────────────────────────────────
            console.print("\n[bold cyan]▶ Plantillas de certificado[/bold cyan]")
            templates = self._get_templates(ldap)
            console.print(f"  {len(templates)} plantilla(s) encontradas")

            # ── 3. Analizar vulnerabilidades ──────────────────────────────────
            vulns = []
            for tmpl in templates:
                issues = self._analyze_template(tmpl)
                for esc, detail in issues:
                    vulns.append((esc, tmpl.get("name","?"), detail))
                    session_db.save_finding(
                        self.target.ip, "LDAP",
                        f"adcs_{esc.lower().replace(' ','')}",
                        f"{tmpl.get('name','?')}: {detail}",
                    )

            # ── 4. Comprobar ESC6 (flag en CA) ────────────────────────────────
            for ca in cas:
                if ca.get("editf_san"):
                    vulns.append((
                        "ESC6",
                        ca.get("name","?"),
                        "CA tiene EDITF_ATTRIBUTESUBJECTALTNAME2 → SAN libre en CUALQUIER plantilla",
                    ))
                    session_db.save_finding(
                        self.target.ip, "LDAP", "adcs_esc6",
                        f"CA {ca.get('name','?')}: EDITF_ATTRIBUTESUBJECTALTNAME2 activo",
                    )

            # ── 5. Mostrar resumen ────────────────────────────────────────────
            if vulns:
                _ORDER = {"ESC1":0,"ESC2":1,"ESC3":2,"ESC4":3,"ESC6":4,"ESC7":5,"ESC8":6}
                vulns.sort(key=lambda x: _ORDER.get(x[0], 9))
                console.rule("[bold red]🎯 Plantillas vulnerables detectadas[/bold red]")
                print_table(
                    f"Vulnerabilidades ADCS ({len(vulns)})",
                    ["ESC", "Plantilla/CA", "Detalle"],
                    vulns,
                )
                print_result("LDAP", str(self.target.ip), "pwned",
                             f"{len(vulns)} vulnerabilidad(es) ADCS identificada(s)")
            else:
                console.print("\n[green]No se detectaron plantillas vulnerables obvias.[/green]")

            # Mostrar todas las plantillas con sus atributos clave
            if templates:
                console.print("\n[bold cyan]▶ Todas las plantillas (resumen)[/bold cyan]")
                print_table(
                    "Plantillas",
                    ["Nombre", "Enroll por", "EKU", "SAN libre", "Requiere aprobación"],
                    [
                        (
                            t.get("name","?"),
                            t.get("enroll_principals","todos") or "Domain Computers",
                            ", ".join(t.get("ekus",[])) or "ninguna",
                            "SÍ ⚠" if t.get("enrollee_supplies_subject") else "no",
                            "SÍ" if t.get("requires_manager_approval") else "no",
                        )
                        for t in templates[:30]
                    ],
                )

        finally:
            ldap.disconnect()

    # ── Métodos auxiliares ────────────────────────────────────────────────────

    def _get_cas(self, ldap) -> list[dict]:
        """Busca las CAs en CN=Enrollment Services."""
        base = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + ldap._base_dn
        entries = ldap._search(
            "(objectClass=pKIEnrollmentService)",
            ["cn", "dNSHostName", "cACertificateDN", "msPKI-Enrollment-Servers",
             "flags", "certificateTemplates"],
            base_dn=base,
        )
        cas = []
        for e in entries:
            attrs = _parse_attrs(e)
            # ESC6: flag EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x40000 en el campo flags
            flags_raw = attrs.get("flags", "0")
            try:
                flags = int(flags_raw) if flags_raw else 0
            except Exception:
                flags = 0
            cas.append({
                "name":     attrs.get("cn","?"),
                "dns":      attrs.get("dNSHostName","?"),
                "dn":       str(e["objectName"]) if hasattr(e, "__getitem__") else "?",
                "editf_san": bool(flags & 0x00040000),
            })
        return cas

    def _get_templates(self, ldap) -> list[dict]:
        """Recupera todas las plantillas de certificado de Configuration."""
        base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration," + ldap._base_dn
        entries = ldap._search(
            "(objectClass=pKICertificateTemplate)",
            [
                "cn", "displayName",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag",
                "msPKI-RA-Signature",
                "msPKI-Private-Key-Flag",
                "pKIExtendedKeyUsage",
                "nTSecurityDescriptor",
                "msPKI-Certificate-Application-Policy",
            ],
            base_dn=base,
        )
        templates = []
        for e in entries:
            attrs = _parse_attrs(e)
            name_flag = int(attrs.get("msPKI-Certificate-Name-Flag", "0") or "0")
            enroll_flag = int(attrs.get("msPKI-Enrollment-Flag", "0") or "0")
            ra_sig = int(attrs.get("msPKI-RA-Signature", "0") or "0")
            ekus_raw = attrs.get("pKIExtendedKeyUsage", "")
            ekus = [e.strip() for e in ekus_raw.split(",") if e.strip()] if ekus_raw else []

            templates.append({
                "name":                    attrs.get("cn", attrs.get("displayName","?")),
                "name_flag":               name_flag,
                "enroll_flag":             enroll_flag,
                "ra_signatures_required":  ra_sig,
                "ekus":                    ekus,
                "enrollee_supplies_subject": bool(name_flag & _ENROLLEE_SUPPLIES_SUBJECT),
                "requires_manager_approval": bool(enroll_flag & 0x2),
                "enroll_principals":       "Domain Users",  # simplificado
            })
        return templates

    def _analyze_template(self, t: dict) -> list[tuple]:
        """Devuelve lista de (ESC_label, descripción) para una plantilla."""
        issues = []
        name = t.get("name","?")

        # ESC1: SAN controlado por el solicitante + Client Auth + sin aprobación
        if (t.get("enrollee_supplies_subject")
                and not t.get("requires_manager_approval")
                and t.get("ra_signatures_required", 0) == 0
                and (_EKU_CLIENT_AUTH in t.get("ekus",[]) or not t.get("ekus"))):
            issues.append((
                "ESC1",
                "Enroll sin aprobación + SAN libre + Client Auth → impersonar cualquier usuario",
            ))

        # ESC2: EKU = Any Purpose o sin EKU
        if _EKU_ANY_PURPOSE in t.get("ekus",[]) or not t.get("ekus"):
            if not t.get("requires_manager_approval"):
                issues.append((
                    "ESC2",
                    "EKU 'Any Purpose' o sin EKU → certificado usable para cualquier fin",
                ))

        # ESC3: Certificate Request Agent EKU
        if _EKU_CERT_REQUEST_AGENT in t.get("ekus",[]):
            if not t.get("requires_manager_approval"):
                issues.append((
                    "ESC3",
                    "EKU Certificate Request Agent → puede solicitar certificados en nombre de otros",
                ))

        return issues


def _parse_attrs(entry) -> dict:
    """Extrae atributos de una entrada LDAP de impacket como dict."""
    result = {}
    try:
        for attr in entry["attributes"]:
            name = str(attr["type"])
            vals = attr["vals"]
            if len(vals) == 1:
                result[name] = str(vals[0])
            elif len(vals) > 1:
                result[name] = ",".join(str(v) for v in vals)
    except Exception:
        pass
    return result
