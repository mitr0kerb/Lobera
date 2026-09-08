
# scripts/smb/enum/os_info.py
"""Detailed OS info via SMB + SRVSVC: build, version, server type."""
from core.output import console, print_result
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, srvs
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    _OK = True
except ImportError:
    _OK = False


class Script(BaseScript):
    name        = "os-info"
    protocol    = "smb"
    category    = "enum"
    description = "Detailed OS info via SMB/RPC: hostname, OS, build, arch, domain role."

    def run(self, **kwargs):
        if not _OK:
            console.print("[red]impacket not installed.[/red]"); return None

        ip      = self.target.ip
        domain  = self.creds.domain   or ""
        user    = self.creds.user     or ""
        passwd  = self.creds.password or ""
        nt_hash = self.creds.hash     or ""
        timeout = self.target.timeout or 5
        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        info = {}
        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
            info["hostname"] = conn.getServerName()          or "—"
            info["os"]       = conn.getServerOS()            or "—"
            info["domain"]   = conn.getServerDomain()        or "—"
            info["dns"]      = conn.getServerDNSDomainName() or "—"
            d = conn.getDialect()
            info["dialect"]  = {
                0x0202:"SMBv2.0", 0x0210:"SMBv2.1",
                0x0300:"SMBv3.0", 0x0302:"SMBv3.0.2", 0x0311:"SMBv3.1.1",
            }.get(d, f"SMBv1/Unknown (0x{d:04x})")
            info["signing"]  = "Required" if conn.isSigningRequired() else "Not required"
            try:
                rpctransport = transport.SMBTransport(ip, filename="\\\\srvsvc", smb_connection=conn)
                dce = rpctransport.get_dce_rpc()
                dce.connect(); dce.bind(srvs.MSRPC_UUID_SRVS)
                resp = srvs.hNetrServerGetInfo(dce, 101)
                srv  = resp["InfoStruct"]["ServerInfo101"]
                info["version"] = f"{srv['sv101_version_major']}.{srv['sv101_version_minor']}"
                info["comment"] = str(srv["sv101_comment"]).strip("\x00") or "—"
                dce.disconnect()
            except Exception:
                pass
            conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"Connection failed: {e}"); return None

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column(style="dim", width=18)
        t.add_column(style="bold")
        for label, key in [
            ("Hostname","hostname"),("OS","os"),("Domain","domain"),
            ("DNS Domain","dns"),("SMB Dialect","dialect"),
            ("SMB Signing","signing"),("Version","version"),("Comment","comment"),
        ]:
            if key in info:
                t.add_row(label, info[key])

        console.print(Panel(t, title=f"[bold green]OS Info — {ip}[/bold green]",
                            border_style="green", expand=False, padding=(1,2)))
        session_db.DB.SaveTarget(ip, info.get("hostname",""), info.get("domain",""))
        session_db.DB.SaveFinding(ip, "SMB", "os_info",
                                   f"os={info.get('os','?')} dialect={info.get('dialect','?')}")
        return info
