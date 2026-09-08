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
        SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30,
        SMB2_NEGOTIATE_SIGNING_REQUIRED,
    )
    _IMPACKET_OK = True
except ImportError:
    _IMPACKET_OK = False
 
 
# ── Dialect helper ────────────────────────────────────────────────────────────
 
_DIALECT_MAP = {
    0x0001: "SMBv1",
    0x0202: "SMBv2.0",
    0x0210: "SMBv2.1",
    0x0300: "SMBv3.0",
    0x0302: "SMBv3.0.2",
    0x0311: "SMBv3.1.1",
}
 
def _dialect_str(raw):
    try:
        d = int(raw)
    except (TypeError, ValueError):
        try:
            d = int.from_bytes(raw, "little")
        except Exception:
            return str(raw)
    return _DIALECT_MAP.get(d, f"Unknown (0x{d:04x})")
 
 
# ── Info extraction ───────────────────────────────────────────────────────────
 
def _get_info(ip, timeout, dialect=None):
    """
    Connect with the given dialect, do anonymous login to trigger
    NTLM challenge processing, then read all server info fields.
    Returns dict or None on failure.
    """
    try:
        if dialect is not None:
            conn = SMBConnection(ip, ip, timeout=timeout, preferredDialect=dialect)
        else:
            conn = SMBConnection(ip, ip, timeout=timeout)
 
        # Anonymous login — this triggers NTLM challenge on SMBv2/3
        # which populates ServerOS from the Version field
        try:
            conn.login("", "", "")
        except Exception:
            pass  # Login may fail (null session denied) but OS is already populated
 
        info = {
            "hostname":   conn.getServerName()          or "",
            "os":         conn.getServerOS()            or "",
            "domain":     conn.getServerDomain()        or "",
            "dns_domain": conn.getServerDNSDomainName() or "",
            "dns_host":   "",
            "dialect_raw": conn.getDialect(),
        }
 
        # Try dns host name too
        try:
            info["dns_host"] = conn.getServerDNSHostName() or ""
        except Exception:
            pass
 
        # OS build fallback
        if not info["os"]:
            try:
                major = conn.getServerOSMajor()
                minor = conn.getServerOSMinor()
                build = conn.getServerOSBuild()
                if major:
                    info["os"] = f"Windows {major}.{minor} Build {build}"
            except Exception:
                pass
 
        # Signing
        try:
            sec = conn._SMBConnection._Connection.get("ServerSecurityMode", None)
            if sec is not None:
                info["signing"] = bool(int(sec) & SMB2_NEGOTIATE_SIGNING_REQUIRED)
            else:
                info["signing"] = conn.isSigningRequired()
        except Exception:
            try:
                info["signing"] = conn.isSigningRequired()
            except Exception:
                info["signing"] = None
 
        try:
            conn.logoff()
        except Exception:
            pass
 
        return info
    except Exception:
        return None
 
 
# ── EternalBlue probe ─────────────────────────────────────────────────────────
 
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
    MS17-010 probe.
    Sends SMBv1 Negotiate → anonymous SessionSetup → TreeConnect IPC$ → Trans2.
    STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) = vulnerable.
    """
    # Step 1: SMBv1 Negotiate
    neg = (
        b"\x00\x00\x00\x54"
        + b"\xff\x53\x4d\x42\x72"
        + b"\x00\x00\x00\x00"
        + b"\x18\x01\x28\x00"
        + b"\x00" * 12
        + b"\x00\x00\xff\xff\xfe\xff\x00\x00\x00\x00"
        + b"\x00"
        + b"\x0c\x00"
        + b"\x02NT LM 0.12\x00"
    )
    r1 = _raw_connect(ip, neg, timeout)
    if not r1 or len(r1) < 36:
        return False
    if r1[8] != 0x72 or struct.unpack_from("<I", r1, 9)[0] != 0:
        return False  # Server rejected SMBv1 negotiate → not vulnerable
 
    # Step 2: Anonymous SessionSetup
    uid = struct.unpack_from("<H", r1, 28)[0] if len(r1) > 29 else 0
    setup = (
        b"\x00\x00\x00\x63"
        + b"\xff\x53\x4d\x42\x73"
        + b"\x00\x00\x00\x00"
        + b"\x18\x07\xc0\x00"
        + b"\x00" * 12
        + b"\x00\x00\xff\xff\xfe\xff"
        + struct.pack("<H", uid)
        + b"\x40\x00"
        + b"\x0d\xff\x00\x00\x00\xff\xff\x02\x00\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x40\x00\x00\x00\x00\x00\x00\x00\x26\x00"
        + b"\x00\x00"
        + b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
        + b"\x01\x00\x00\x00"
        + b"\x97\x82\x08\xe2"
        + b"\x00" * 16
        + b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"
    )
    r2 = _raw_connect(ip, setup, timeout)
    if not r2 or len(r2) < 36:
        return None
    uid2 = struct.unpack_from("<H", r2, 28)[0] if len(r2) > 29 else uid
 
    # Step 3: TreeConnect to IPC$
    ipc = b"\\\\" + ip.encode() + b"\\IPC$\x00"
    padding = b"\x00" * ((4 - len(ipc) % 4) % 4)
    tree = (
        b"\x00\x00\x00\x44"
        + b"\xff\x53\x4d\x42\x75"
        + b"\x00\x00\x00\x00"
        + b"\x18\x07\xc0\x00"
        + b"\x00" * 12
        + b"\x00\x00\xff\xff\xfe\xff"
        + struct.pack("<H", uid2)
        + b"\x40\x00"
        + b"\x04\xff\x00\x00\x00\x00\x00"
        + struct.pack("<H", len(ipc) + len(padding) + 3)
        + b"\x00\x00\x00\x00\x00"
        + b"\x01"
        + struct.pack("<H", len(ipc) + len(padding))
        + ipc + padding
        + b"?????\x00"
    )
    r3 = _raw_connect(ip, tree, timeout)
    if not r3 or len(r3) < 36:
        return None
    status3 = struct.unpack_from("<I", r3, 9)[0]
    if status3 != 0:
        return None
    tid = struct.unpack_from("<H", r3, 24)[0] if len(r3) > 25 else 0
 
    # Step 4: Trans2 with special FEA list — triggers pool grooming
    trans2 = (
        b"\x00\x00\x00\x9f"
        + b"\xff\x53\x4d\x42\x32"
        + b"\x00\x00\x00\x00"
        + b"\x18\x07\xc0\x00"
        + b"\x00" * 12
        + struct.pack("<H", tid)
        + b"\xfe\xff"
        + struct.pack("<H", uid2)
        + b"\x40\x00"
        + b"\x0f"
        + b"\x00" * 30
        + b"\x4a\x00"
        + b"\x00" * 78
    )
    r4 = _raw_connect(ip, trans2, timeout)
    if not r4 or len(r4) < 13:
        return None
 
    status4 = struct.unpack_from("<I", r4, 9)[0]
    if status4 == 0xC0000205:   # STATUS_INSUFF_SERVER_RESOURCES → vulnerable
        return True
    if status4 in (0x00000000, 0xC0000034, 0xC0000022, 0xC000006D):
        return False
    return None   # inconclusive
 
 
def _check_smbghost(ip, timeout=5):
    """CVE-2020-0796: SMBv3.1.1 compression context detection."""
    payload = (
        b"\x00\x00\x00\xc0"
        + b"\xfeSMB"
        + b"\x40\x00" + b"\x00\x00\x00\x00" + b"\x00\x00" + b"\x1f\x00"
        + b"\x00\x00\x00\x00" + b"\x00" * 8 + b"\x00" * 4 + b"\x00" * 4
        + b"\x00" * 8 + b"\x00" * 16
        + b"\x24\x00" + b"\x02\x00" + b"\x01\x00" + b"\x00\x00"
        + b"\x7f\x00\x00\x00" + b"\x00" * 16
        + b"\x78\x00\x00\x00" + b"\x02\x00" + b"\x00\x00"
        + b"\x02\x03" + b"\x11\x03" + b"\x00\x00"
        + b"\x01\x00" + b"\x26\x00" + b"\x00\x00\x00\x00"
        + b"\x01\x00" + b"\x20\x00" + b"\x01\x00" + b"\x00" * 32
        + b"\x03\x00" + b"\x06\x00" + b"\x00\x00\x00\x00"
        + b"\x01\x00" + b"\x02\x00"
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
 
        # ── Step 1: try SMBv1 with login → richest OS info ────────────────────
        console.print("[dim][analysis] Trying SMBv1 (with anonymous login)...[/dim]")
        info1 = _get_info(ip, timeout, dialect=SMB_DIALECT)
        if info1:
            r["smbv1"] = True
            r["dialect"] = "SMBv1"
            for key in ("hostname", "os", "domain", "dns_domain", "signing"):
                val = info1.get(key)
                if val and val != "":
                    r[key] = val
 
        # ── Step 2: SMBv2/3 with login → fills OS from NTLM Version field ─────
        console.print("[dim][analysis] Connecting via SMBv2/3 (with anonymous login)...[/dim]")
        info3 = _get_info(ip, timeout, dialect=None)
        if info3:
            # Fill gaps — prefer non-empty values
            for key in ("hostname", "os", "domain", "dns_domain"):
                if (r[key] == "—" or r[key] == "") and info3.get(key):
                    r[key] = info3[key]
 
            # Dialect from v3 connection (keep SMBv1 if that was set)
            d_str = _dialect_str(info3.get("dialect_raw", 0))
            if r["dialect"] == "—":
                r["dialect"] = d_str
            elif r["smbv1"] and d_str not in ("SMBv1", "Unknown (0x0001)"):
                r["dialect"] = f"SMBv1 + {d_str}"
 
            # Signing from v3 if not yet set
            if r["signing"] is None:
                r["signing"] = info3.get("signing")
 
        elif info1 is None:
            console.print(f"[red]Cannot connect to {ip}:445[/red]")
            return None
 
        # ── Step 3: DC detection ──────────────────────────────────────────────
        dns = r["dns_domain"]
        if dns and dns != "—" and "." in dns:
            r["is_dc"] = True
 
        # ── Step 4: null session ──────────────────────────────────────────────
        console.print("[dim][analysis] Testing null session...[/dim]")
        try:
            cn = SMBConnection(ip, ip, timeout=timeout)
            cn.login("", "", "")
            # If login raised no exception, null session is allowed
            r["null_sess"] = True
            try: cn.logoff()
            except Exception: pass
        except Exception as e:
            err = str(e).lower()
            # Some servers allow the session but return STATUS_ACCESS_DENIED later
            r["null_sess"] = "logon_failure" not in err and "access_denied" not in err
 
        # ── Step 5: vulnerability probes ──────────────────────────────────────
        console.print("[dim][analysis] Checking EternalBlue (MS17-010)...[/dim]")
        r["eternalblue"] = _check_eternalblue(ip, timeout)
 
        console.print("[dim][analysis] Checking SMBGhost (CVE-2020-0796)...[/dim]")
        r["smbghost"]    = _check_smbghost(ip, timeout)
 
        # ── Step 6: save to DB ────────────────────────────────────────────────
        hn  = r["hostname"]   if r["hostname"]   not in ("—", "") else ""
        dom = r["domain"]     if r["domain"]     not in ("—", "") else ""
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
    signing_str = (
        "[dim]Unknown[/dim]" if r["signing"] is None
        else "[green]Required ✓[/green]" if r["signing"]
        else "[bold red]Not required ✗  (NTLM relay possible)[/bold red]"
    )
    null_str = (
        "[dim]Unknown[/dim]"         if r["null_sess"] is None
        else "[bold red]Allowed ✗[/bold red]" if r["null_sess"]
        else "[green]Denied ✓[/green]"
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
