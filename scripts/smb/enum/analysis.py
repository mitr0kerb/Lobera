# scripts/smb/enum/analysis.py
"""
SMB host analysis — full recon from a single IP.
No credentials required for base info.
Null session used automatically if available for extra data.

Reports: hostname, OS, domain, DC flag, SMB dialect, signing,
         null session, EternalBlue (MS17-010), SMBGhost (CVE-2020-0796).
"""

import socket
import struct

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group
from rich import box

from core.output import console
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.smb import SMB_DIALECT
    from impacket.smb3structs import SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30
    _IMPACKET_OK = True
except ImportError:
    _IMPACKET_OK = False


# ── Low-level helpers ─────────────────────────────────────────────────────────

def _raw_connect(ip, payload, timeout=5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 445))
        s.send(payload)
        resp = s.recv(4096)
        s.close()
        return resp
    except Exception:
        return None


def _check_eternalblue(ip, timeout=5):
    """
    MS17-010 probe: sends a minimal SMBv1 Negotiate packet.
    If the server replies with a valid SMBv1 Negotiate response
    (command=0x72, NT_STATUS=0) it supports SMBv1 and may be vulnerable.
    """
    payload = (
        b"\x00\x00\x00\x54"                          # NetBIOS header
        + b"\xff\x53\x4d\x42"                         # SMB magic
        + b"\x72"                                      # Cmd: Negotiate (0x72)
        + b"\x00\x00\x00\x00"                         # NT Status
        + b"\x18\x01\x28\x00"                         # Flags / Flags2
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"        # Signature
        + b"\x00\x00"                                  # Reserved
        + b"\xff\xff"                                  # TID
        + b"\xfe\xff"                                  # PID
        + b"\x00\x00"                                  # UID
        + b"\x00\x00"                                  # MID
        + b"\x00"                                      # WordCount = 0
        + b"\x0c\x00"                                  # ByteCount = 12
        + b"\x02NT LM 0.12\x00"                       # Dialect string
    )
    resp = _raw_connect(ip, payload, timeout)
    if resp and len(resp) > 13:
        cmd    = resp[8]
        status = struct.unpack_from("<I", resp, 9)[0]
        if cmd == 0x72 and status == 0:
            return True
    return False


def _check_smbghost(ip, timeout=5):
    """
    CVE-2020-0796 (SMBGhost) probe: SMBv3.1.1 Negotiate with
    SMB2_COMPRESSION_CAPABILITIES context.
    If the server echoes back type 0x0003 in its Negotiate response,
    compression is active and the host may be vulnerable.
    """
    payload = (
        b"\x00\x00\x00\xc0"                           # NetBIOS length
        + b"\xfeSMB"                                   # SMB2 magic
        + b"\x40\x00"                                  # StructureSize=64
        + b"\x00\x00\x00\x00"                         # CreditCharge/Status
        + b"\x00\x00"                                  # Command: Negotiate
        + b"\x1f\x00"                                  # CreditRequest
        + b"\x00\x00\x00\x00"                         # Flags
        + b"\x00" * 8                                  # MessageId
        + b"\x00" * 4                                  # Reserved
        + b"\x00" * 4                                  # TreeId
        + b"\x00" * 8                                  # SessionId
        + b"\x00" * 16                                 # Signature
        + b"\x24\x00"                                  # Body StructureSize
        + b"\x02\x00"                                  # DialectCount=2
        + b"\x01\x00"                                  # SecurityMode
        + b"\x00\x00"                                  # Reserved
        + b"\x7f\x00\x00\x00"                         # Capabilities
        + b"\x00" * 16                                 # ClientGuid
        + b"\x78\x00\x00\x00"                         # NegotiateContextOffset
        + b"\x02\x00"                                  # NegotiateContextCount
        + b"\x00\x00"                                  # Reserved
        + b"\x02\x03"                                  # Dialect 0x0302
        + b"\x11\x03"                                  # Dialect 0x0311
        + b"\x00\x00"                                  # Padding
        + b"\x01\x00"                                  # PREAUTH_INTEGRITY type
        + b"\x26\x00"                                  # DataLength=38
        + b"\x00\x00\x00\x00"                         # Reserved
        + b"\x01\x00"                                  # HashAlgorithmCount
        + b"\x20\x00"                                  # SaltLength=32
        + b"\x01\x00"                                  # SHA-512
        + b"\x00" * 32                                 # Salt
        + b"\x03\x00"                                  # COMPRESSION_CAPABILITIES type
        + b"\x06\x00"                                  # DataLength=6
        + b"\x00\x00\x00\x00"                         # Reserved
        + b"\x01\x00"                                  # CompressionAlgorithmCount
        + b"\x02\x00"                                  # LZNT1
    )
    resp = _raw_connect(ip, payload, timeout)
    if resp and b"\x03\x00" in resp[100:]:
        return True
    return False


# ── Script ────────────────────────────────────────────────────────────────────

class Script(BaseScript):
    name        = "analysis"
    protocol    = "smb"
    category    = "enum"
    description = (
        "Full SMB host recon: OS, hostname, domain, DC, dialect, signing, "
        "null session, EternalBlue (MS17-010), SMBGhost (CVE-2020-0796)."
    )

    def run(self, **kwargs):
        if not _IMPACKET_OK:
            console.print("[red]impacket not installed.[/red]")
            return None

        ip      = self.target.ip
        timeout = self.target.timeout or 5

        console.print(f"\n[dim][analysis] Probing {ip}...[/dim]")

        r = {
            "hostname":    "—",
            "os":          "—",
            "domain":      "—",
            "dns_domain":  "—",
            "is_dc":       None,
            "dialect":     "—",
            "signing":     None,
            "null_sess":   None,
            "eternalblue": None,
            "smbghost":    None,
        }

        # ── impacket anonymous connect ─────────────────────────────────────
        try:
            conn = SMBConnection(ip, ip, timeout=timeout)

            d = conn.getDialect()
            r["dialect"] = {
                SMB_DIALECT:      "SMBv1",
                SMB2_DIALECT_002: "SMBv2.0",
                SMB2_DIALECT_21:  "SMBv2.1",
                SMB2_DIALECT_30:  "SMBv3.0",
            }.get(d, f"SMBv3.x (0x{d:04x})")

            r["signing"] = conn.isSigningRequired()

            try:
                r["hostname"]   = conn.getServerName()          or "—"
                r["os"]         = conn.getServerOS()            or "—"
                r["domain"]     = conn.getServerDomain()        or "—"
                r["dns_domain"] = conn.getServerDNSDomainName() or "—"
                if r["dns_domain"] != "—" and r["domain"] != "—":
                    r["is_dc"] = r["dns_domain"].lower().startswith(
                        r["domain"].lower()
                    )
            except Exception:
                pass

            try:
                conn.login("", "", "")
                r["null_sess"] = True
                conn.logoff()
            except Exception:
                r["null_sess"] = False
                try:
                    conn.close()
                except Exception:
                    pass

        except Exception as e:
            console.print(f"[red]Connection failed: {e}[/red]")
            return None

        # ── Vulnerability probes ───────────────────────────────────────────
        console.print("[dim][analysis] Checking EternalBlue (MS17-010)...[/dim]")
        r["eternalblue"] = _check_eternalblue(ip, timeout)

        console.print("[dim][analysis] Checking SMBGhost (CVE-2020-0796)...[/dim]")
        r["smbghost"]    = _check_smbghost(ip, timeout)

        # ── Save findings ──────────────────────────────────────────────────
        session_db.DB.SaveTarget(ip, r["hostname"], r["domain"])

        if r["signing"] is False:
            session_db.DB.SaveFinding(ip, "SMB", "signing_not_required",
                                       "SMB signing not required — NTLM relay possible")
        if r["null_sess"]:
            session_db.DB.SaveFinding(ip, "SMB", "null_session", "Null session allowed")
        if r["eternalblue"]:
            session_db.DB.SaveFinding(ip, "SMB", "eternalblue",
                                       "MS17-010 — SMBv1 negotiate succeeded")
        if r["smbghost"]:
            session_db.DB.SaveFinding(ip, "SMB", "smbghost",
                                       "CVE-2020-0796 — SMBv3.1.1 compression context detected")

        # ── Render ─────────────────────────────────────────────────────────
        _render(ip, r)
        return r


def _render(ip, r):

    def _bool(val, good_if_true=True, yes="Yes", no="No"):
        if val is None:
            return "[dim]Unknown[/dim]"
        good  = (val and good_if_true) or (not val and not good_if_true)
        color = "green" if good else "red"
        mark  = "✓" if good else "✗"
        label = yes if val else no
        return f"[{color}]{label} {mark}[/{color}]"

    # ── Host info ──────────────────────────────────────────────────────────
    host = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    host.add_column(style="dim",  width=16)
    host.add_column()

    host.add_row("Hostname",    f"[bold]{r['hostname']}[/bold]")
    host.add_row("OS",          r["os"])
    host.add_row("Domain",      r["domain"])
    host.add_row("DNS Domain",  r["dns_domain"])
    host.add_row("Is DC",       _bool(r["is_dc"]))
    host.add_row("SMB Dialect", f"[cyan]{r['dialect']}[/cyan]")

    # ── Security ───────────────────────────────────────────────────────────
    sec = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    sec.add_column(style="dim", width=16)
    sec.add_column()

    if r["signing"] is None:
        signing_str = "[dim]Unknown[/dim]"
    elif r["signing"]:
        signing_str = "[green]Required ✓  (protected against NTLM relay)[/green]"
    else:
        signing_str = "[bold red]Not required ✗  (NTLM relay possible)[/bold red]"

    if r["null_sess"] is None:
        null_str = "[dim]Unknown[/dim]"
    elif r["null_sess"]:
        null_str = "[bold red]Allowed ✗  (unauthenticated enumeration possible)[/bold red]"
    else:
        null_str = "[green]Denied ✓[/green]"

    sec.add_row("SMB Signing",  signing_str)
    sec.add_row("Null Session", null_str)

    # ── Vulnerabilities ────────────────────────────────────────────────────
    vuln = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    vuln.add_column(style="dim", width=22)
    vuln.add_column()

    def vuln_row(label, val, cve=""):
        tag = f"  [dim]({cve})[/dim]" if cve else ""
        if val is True:
            vuln.add_row(label, f"[bold red]POTENTIALLY VULNERABLE ✗[/bold red]{tag}")
        elif val is False:
            vuln.add_row(label, f"[green]Not vulnerable ✓[/green]{tag}")
        else:
            vuln.add_row(label, f"[dim]Inconclusive[/dim]{tag}")

    vuln_row("EternalBlue",  r["eternalblue"], "MS17-010")
    vuln_row("SMBGhost",     r["smbghost"],    "CVE-2020-0796")

    # ── Panel ──────────────────────────────────────────────────────────────
    console.print(Panel(
        Group(
            Text("HOST INFORMATION", style="bold green"),
            host,
            Text(""),
            Text("SECURITY", style="bold green"),
            sec,
            Text(""),
            Text("VULNERABILITIES", style="bold green"),
            vuln,
        ),
        title=f"[bold green]  SMB Analysis — {ip}  [/bold green]",
        border_style="green",
        expand=False,
        padding=(1, 3),
    ))
