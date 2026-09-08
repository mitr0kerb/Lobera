# scripts/smb/enum/auth.py
"""
SMB authentication test.
Tries to authenticate with the given credentials and reports
whether they are valid. Supports password, NT hash and null session.
"""

from core.output import console, print_result
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection, SessionError
    _IMPACKET_OK = True
except ImportError:
    _IMPACKET_OK = False


class Script(BaseScript):
    name        = "auth"
    protocol    = "smb"
    category    = "enum"
    description = "Test SMB credentials (password, hash or null session) and report result."

    def run(self, **kwargs):
        if not _IMPACKET_OK:
            console.print("[red]impacket not installed.[/red]")
            return False

        ip      = self.target.ip
        domain  = self.creds.domain   or ""
        user    = self.creds.user     or ""
        passwd  = self.creds.password or ""
        nt_hash = self.creds.hash     or ""
        timeout = self.target.timeout or 5

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        if not user and not passwd and not nt_hash:
            mode = "null session"
        elif nt_hash:
            mode = f"pass-the-hash ({user})"
        else:
            mode = f"password ({user})"

        console.print(f"\n[dim]Trying {mode} against {ip}...[/dim]")

        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
            dialect = {
                0x0202: "SMBv2.0", 0x0210: "SMBv2.1",
                0x0300: "SMBv3.0", 0x0302: "SMBv3.0.2", 0x0311: "SMBv3.1.1",
            }.get(conn.getDialect(), "SMBv1")
        except SessionError as e:
            print_result("SMB", ip, "fail", f"Authentication failed — {e}")
            return False
        except Exception as e:
            print_result("SMB", ip, "fail", f"Connection error — {e}")
            return False

        from rich.panel import Panel
        from rich.table import Table
        from rich import box

        if not user:
            print_result("SMB", ip, "ok", "Null session allowed")
            session_db.DB.SaveFinding(ip, "SMB", "null_session", "null session allowed")
            conn.logoff()
            return True

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column(style="bold green", width=16)
        t.add_column(style="white")

        t.add_row("User",    user)
        t.add_row("Domain",  domain or "(none)")
        t.add_row("Auth",    "Hash (PTH)" if self.creds.hash else "Password")
        t.add_row("Dialect", dialect)

        server_name = "—"
        try:
            server_name = conn.getServerName()   or "—"
            server_os   = conn.getServerOS()     or "—"
            server_dom  = conn.getServerDomain() or "—"
            t.add_row("Hostname",      server_name)
            t.add_row("Server OS",     server_os)
            t.add_row("Server Domain", server_dom)
        except Exception:
            pass

        console.print(Panel(
            t,
            title=f"[bold green]✓  Authentication successful — {ip}[/bold green]",
            border_style="green",
            expand=False,
        ))

        secret      = self.creds.hash or passwd
        secret_type = "hash" if self.creds.hash else "password"
        session_db.DB.SaveCredential(ip, user, secret, secret_type, True, "smb_auth")
        session_db.DB.SaveTarget(ip, server_name, domain)

        conn.logoff()
        return True
