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

from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.console import Group
from rich         import box

from core.output  import console
from core         import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.smb           import SMB_DIALECT
    from impacket.smb3structs   import (
        SMB2_DIALECT_002, SMB2_DIALECT_21,
        SMB2_DIALECT_30, SMB2_NEGOTIATE_SIGNING_REQUIRED,
    )
    _IMPACKET_OK = True
except ImportError:
    _IMPACKET_OK = False


# ── Raw socket helpers ────────────────────────────────────────────────────────

def _raw_probe(ip, payload, timeout=5):
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
    MS17-010 probe using Trans2 STATUS_INSUFF_SERVER_RESOURCES technique.
    Returns True = likely vulnerable, False = patched, None = inconclusive.
    """
    # Negotiate SMBv1
    neg = (
        b"\x00\x00\x00\x54"
        + b"\xff\x53\x4d\x42\x72"
        + b"\x00\x00\x00\x00"
        + b"\x18\x01\x28\x00"
        + b"\x00" * 8
        + b"\x00\x00\xff\xff\xfe\xff\x00\x00\x00\x00"
        + b"\x00"
        + b"\x0c\x00"
        + b"\x02NT LM 0.12\x00"
    )
    r1 = _raw_probe(ip, neg, timeout)
    if not r1 or len(r1) < 36:
        return False
    if r1[8] != 0x72 or struct.unpack_from("<I", r1, 9)[0] != 0:
        return False

    # Anonymous SessionSetup
    uid = struct.unpack_from("<H", r1, 28)[0] if len(r1) > 29 else 0
    setup = (
        b"\x00\x00\x00\x63"
        + b"\xff\x53\x4d\x42\x73"
        + b"\x00\x00\x00\x00"
        + b"\x18\x07\xc0\x00"
        + b"\x00" * 8
        + b"\x00\x00\xff\xff\xfe\xff"
        + struct.pack("<H", uid)
        + b"\x40\x00"
        + b"\x0d\xff\x00\x00\x00\xff\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x40\x00\x00\x00\x00\x00\x00\x00\x26\x00"
        + b"\x00\x00"
        + b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
        + b"\x01\x00\x00\x00"
        + b"\x97\x82\x08\xe2"
        + b"\x00" * 16
        + b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"
    )
    r2 = _raw_probe(ip, setup, timeout)
    if not r2 or len(r2) < 36:
        return None
    uid2 = struct.unpack_from("<H", r2, 28)[0] if len(r2) > 29 else uid

    # Tree connect IPC$
    ipc_path = ("\\\\\\\\%s\\\\IPC$\x00" % ip).encode()
    tree = (
        b"\x00\x00\x00\x49"
        + b"\xff\x53\x4d\x42\x75"
        + b"\x00\x00\x00\x00"
        + b"\x18\x07\xc0\x00"
        + b"\x00" * 8
        + b"\x00\x00\xff\xff\xfe\xff"
        + struct.pack("<H", uid2)
        + b"\x40\x00"
        + b"\x04\xff\x00\x00\x00\x00\x00\x31\x00\x00\x00\x00\x00"
        + b"\x01"
        + b"\x00"
        + struct.pack("<H", len(ipc_path) + 3)
        + b"\\\\".encode()
        + ip.encode()
        + b"\\" .encode()
        + b"IPC$\x00NTLANSSP\x00"
    )
    r3 = _raw_probe(ip, tree, timeout)
    if not r3 or len(r3) < 36:
        return None
    if struct.unpack_from("<I", r3, 9)[0] != 0:
        return None
    tid = struct.unpack_from("<H", r3, 24)[0] if len(r3) > 25 else 0

    # Trans2 SESSION_SETUP with pool-grooming FEA list
    trans2 = (
        b"\x00\x00\x00\x9f"
        + b"\xff\x53\x4d\x42\x32"
        + b"\x00\x00\x00\x00"
        + b"\x18\x07\xc0\x00"
        + b"\x00" * 8
        + struct.pack("<H", tid)
        + b"\xfe\xff"
        + struct.pack("<H", uid2)
        + b"\x40\x00"
        + b"\x0f"
        + b"\x00" * 28
        + b"\x00\x00\x00\x00"
        + b"\x4a\x00"
        + b"\x00" * 4
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    r4 = _raw_probe(ip, trans2, timeout)
    if not r4 or len(r4) < 13:
        return None
    status4 = struct.unpack_from("<I", r4, 9)[0]
    if status4 == 0xC0000205:   # STATUS_INSUFF_SERVER_RESOURCES
        return True
    if status4 in (0x00000000, 0xC0000034, 0xC0000022):
        return False
    return None


def _check_smbghost(ip, timeout=5):
    """CVE-2020-0796: compression context in SMBv3.1.1 negotiate response."""
    payload = (
        b"\x00\x00\x00\xc0"
        + b"\xfeSMB"
        + b"\x40\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00"
        + b"\x1f\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00" * 8
        + b"\x00" * 4
        + b"\x00" * 4
        + b"\x00" * 8
        + b"\x00" * 16
        + b"\x24\x00"
        + b"\x02\x00"
        + b"\x01\x00"
        + b"\x00\x00"
        + b"\x7f\x00\x00\x00"
        + b"\x00" * 16
        + b"\x78\x00\x00\x00"
        + b"\x02\x00"
        + b"\x00\x00"
        + b"\x02\x03"
        + b"\x11\x03"
        + b"\x00\x00"
        + b"\x01\x00"
        + b"\x26\x00"
        + b"\x00\x00\x00\x00"
        + b"\x01\x00"
        + b"\x20\x00"
        + b"\x01\x00"
        + b"\x00" * 32
        + b"\x03\x00"
        + b"\x06\x00"
        + b"\x00\x00\x00\x00"
        + b"\x01\x00"
        + b"\x02\x00"
    )
    resp = _raw_probe(ip, payload, timeout)
    if resp and b"\x03\x00" in resp[100:]:
        return True
    return False


def _dialect_name(d):
    try:
        di = int(d)
    except (TypeError, ValueError):
        return str(d)
    return {
        0x0001: "SMBv1",
        0x0202: "SMBv2.0",
        0x0210: "SMBv2.1",
        0x0300: "SMBv3.0",
        0x0302: "SMBv3.0.2",
        0x0311: "SMBv3.1.1",
    }.get(di, f"Unknown (0x{di:04x})")


# ── Script ────────────────────────────────────────────────────────────────────

class Script(BaseScript):
    name        = "analysis"
    protocol    = "smb"
    category    = "enum"
    description = (
        "Full SMB host recon: OS, hostname, domain, DC, dialect, signing, SMBv1, "
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
            "is_dc":       False,
            "dialect":     "—",
            "smbv1":       False,
            "signing":     None,
            "null_sess":   None,
            "eternalblue": None,
            "smbghost":    None,
        }

        # ── 1. Try SMBv1 first (richer NativeOS string) ───────────────────────
        console.print("[dim][analysis] Trying SMBv1...[/dim]")
        try:
            c1 = SMBConnection(ip, ip, timeout=timeout, preferredDialect=SMB_DIALECT)
            r["hostname"]   = c1.getServerName()          or r["hostname"]
            r["os"]         = c1.getServerOS()            or r["os"]
            r["domain"]     = c1.getServerDomain()        or r["domain"]
            r["dns_domain"] = c1.getServerDNSDomainName() or r["dns_domain"]
            r["dialect"]    = "SMBv1"
            r["smbv1"]      = True
            try: c1.logoff()
            except Exception: pass
        except Exception:
            r["smbv1"] = False

        # ── 2. SMBv2/3 connection ─────────────────────────────────────────────
        console.print("[dim][analysis] Connecting via SMBv2/3...[/dim]")
        try:
            c3 = SMBConnection(ip, ip, timeout=timeout)
            d  = c3.getDialect()

            # Fill gaps from SMBv1
            for key, getter in [
                ("hostname",   c3.getServerName),
                ("domain",     c3.getServerDomain),
                ("dns_domain", c3.getServerDNSDomainName),
            ]:
                if r[key] == "—":
                    try: r[key] = getter() or "—"
                    except Exception: pass

            # OS: try numeric fields first (more reliable on v2/v3)
            if r["os"] == "—":
                try:
                    major = c3.getServerOSMajor()
                    minor = c3.getServerOSMinor()
                    build = c3.getServerOSBuild()
                    if major:
                        r["os"] = f"Windows {major}.{minor} Build {build}"
                except Exception:
                    try: r["os"] = c3.getServerOS() or "—"
                    except Exception: pass

            # Dialect
            d_name = _dialect_name(d)
            if r["dialect"] == "—":
                r["dialect"] = d_name
            elif r["smbv1"] and d_name != "SMBv1":
                r["dialect"] = f"SMBv1 + {d_name}"

            # Signing — most reliable via internal connection state
            try:
                sec = c3._SMBConnection._Connection.get("ServerSecurityMode", None)
                if sec is not None:
                    r["signing"] = bool(int(sec) & SMB2_NEGOTIATE_SIGNING_REQUIRED)
                else:
                    r["signing"] = c3.isSigningRequired()
            except Exception:
                try: r["signing"] = c3.isSigningRequired()
                except Exception: pass

            # DC: has a proper DNS domain (contains a dot)
            dns = r["dns_domain"]
            if dns and dns != "—" and "." in dns:
                r["is_dc"] = True

            # Null session
            console.print("[dim][analysis] Testing null session...[/dim]")
            try:
                cn = SMBConnection(ip, ip, timeout=timeout)
                cn.login("", "", "")
                r["null_sess"] = True
                try: cn.logoff()
                except Exception: pass
            except Exception:
                r["null_sess"] = False

            try: c3.logoff()
            except Exception: pass

        except Exception as e:
            if not r["smbv1"]:
                console.print(f"[red]Connection failed: {e}[/red]")
                return None

        # ── 3. Vulnerability probes ───────────────────────────────────────────
        console.print("[dim][analysis] Checking EternalBlue (MS17-010)...[/dim]")
        r["eternalblue"] = _check_eternalblue(ip, timeout)

        console.print("[dim][analysis] Checking SMBGhost (CVE-2020-0796)...[/dim]")
        r["smbghost"]    = _check_smbghost(ip, timeout)

        # ── 4. Save to DB ─────────────────────────────────────────────────────
        hn  = r["hostname"]  if r["hostname"]  != "—" else ""
        dom = r["domain"]    if r["domain"]    != "—" else ""
        session_db.DB.SaveTarget(ip, hn, dom)

        if r["signing"] is False:
            session_db.DB.SaveFinding(ip, "SMB", "signing_not_required",
                                       "Not required — NTLM relay possible")
        if r["null_sess"]:
            session_db.DB.SaveFinding(ip, "SMB", "null_session", "Null session allowed")
        if r["smbv1"]:
            session_db.DB.SaveFinding(ip, "SMB", "smbv1_enabled", "SMBv1 enabled")
        if r["eternalblue"]:
            session_db.DB.SaveFinding(ip, "SMB", "eternalblue",
                                       "MS17-010 — STATUS_INSUFF_SERVER_RESOURCES")
        if r["smbghost"]:
            session_db.DB.SaveFinding(ip, "SMB", "smbghost",
                                       "CVE-2020-0796 — compression context detected")

        _render(ip, r)
        return r


def _render(ip, r):

    def _bool(val, good_if_true=True, yes="Yes", no="No"):
        if val is None:
            return "[dim]Unknown[/dim]"
        good  = (val and good_if_true) or (not val and not good_if_true)
        color = "green" if good else "red"
        mark  = "✓" if good else "✗"
        return f"[{color}]{yes if val else no} {mark}[/{color}]"

    host = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    host.add_column(style="dim", width=18)
    host.add_column()
    host.add_row("Hostname",    f"[bold]{r['hostname']}[/bold]")
    host.add_row("OS",          r["os"])
    host.add_row("Domain",      r["domain"])
    host.add_row("DNS Domain",  r["dns_domain"])
    host.add_row("Is DC",       _bool(r["is_dc"]))
    host.add_row("SMB Dialect", f"[cyan]{r['dialect']}[/cyan]")
    host.add_row("SMBv1",       _bool(r["smbv1"], good_if_true=False,
                                      yes="Enabled ✗", no="Disabled ✓"))

    sec = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    sec.add_column(style="dim", width=18)
    sec.add_column()
    if r["signing"] is None:
        signing_str = "[dim]Unknown[/dim]"
    elif r["signing"]:
        signing_str = "[green]Required ✓[/green]"
    else:
        signing_str = "[bold red]Not required ✗  (NTLM relay possible)[/bold red]"
    null_str = (
        "[bold red]Allowed ✗[/bold red]" if r["null_sess"]
        else "[green]Denied ✓[/green]"   if r["null_sess"] is False
        else "[dim]Unknown[/dim]"
    )
    sec.add_row("SMB Signing",  signing_str)
    sec.add_row("Null Session", null_str)

    vuln = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    vuln.add_column(style="dim", width=22)
    vuln.add_column()
    def vrow(label, val, cve=""):
        tag = f"  [dim]({cve})[/dim]" if cve else ""
        if val is True:
            vuln.add_row(label, f"[bold red]POTENTIALLY VULNERABLE ✗[/bold red]{tag}")
        elif val is False:
            vuln.add_row(label, f"[green]Not vulnerable ✓[/green]{tag}")
        else:
            vuln.add_row(label, f"[dim]Inconclusive[/dim]{tag}")
    vrow("EternalBlue", r["eternalblue"], "MS17-010")
    vrow("SMBGhost",    r["smbghost"],    "CVE-2020-0796")

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
