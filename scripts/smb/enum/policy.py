
# scripts/smb/enum/policy.py
"""Enumerate password policy via SAMR pipe (no LDAP needed)."""
from core.output import console, print_result
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, samr
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    _OK = True
except ImportError:
    _OK = False


class Script(BaseScript):
    name        = "policy"
    protocol    = "smb"
    category    = "enum"
    description = "Enumerate domain password and lockout policy via SAMR pipe (no LDAP needed)."

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

        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
            rpctransport = transport.SMBTransport(ip, filename="\\\\samr", smb_connection=conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect(); dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]
            resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domain_name = resp2["Buffer"]["Buffer"][0]["Name"]
            resp3 = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
            resp4 = samr.hSamrOpenDomain(dce, server_handle, domainId=resp3["DomainId"])
            dh = resp4["DomainHandle"]

            resp5 = samr.hSamrQueryInformationDomain2(
                dce, dh, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
            pol = resp5["Buffer"]["Password"]
            min_len   = str(pol["MinPasswordLength"])
            pass_hist = str(pol["PasswordHistoryLength"])
            props     = int(pol["PasswordProperties"])
            complexity  = "Enabled"  if props & 0x1  else "Disabled"
            reversible  = "Yes"      if props & 0x10 else "No"

            def _days(val_struct):
                low  = int(val_struct["LowPart"])
                high = int(val_struct["HighPart"])
                raw  = low | (high << 32)
                return abs(raw) // (10_000_000 * 86_400) if raw else 0

            max_age_days = _days(pol["MaxPasswordAge"])
            min_age_days = _days(pol["MinPasswordAge"])

            resp6 = samr.hSamrQueryInformationDomain2(
                dce, dh, samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
            lock = resp6["Buffer"]["Lockout"]
            lockout_threshold = str(lock["LockoutThreshold"])
            lockout_dur_mins  = abs(
                int(lock["LockoutDuration"]["LowPart"]) |
                (int(lock["LockoutDuration"]["HighPart"]) << 32)
            ) // (10_000_000 * 60)

            dce.disconnect(); conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"SAMR error: {e}"); return None

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column(style="dim", width=26)
        t.add_column(style="bold")
        rows = [
            ("Domain",               str(domain_name)),
            ("Min Password Length",  min_len),
            ("Password History",     f"{pass_hist} remembered"),
            ("Max Password Age",     f"{max_age_days} days" if max_age_days else "Never expires"),
            ("Min Password Age",     f"{min_age_days} days" if min_age_days else "No minimum"),
            ("Complexity",           complexity),
            ("Reversible Encryption",reversible),
            ("Lockout Threshold",    f"{lockout_threshold} failed attempts"),
            ("Lockout Duration",     f"{lockout_dur_mins} minutes"),
        ]
        for label, val in rows:
            t.add_row(label, val)

        console.print(Panel(t, title=f"[bold green]Password Policy — {ip}[/bold green]",
                            border_style="green", expand=False, padding=(1,2)))
        session_db.DB.SaveFinding(ip, "SMB", "password_policy",
                                   f"min_len={min_len} complexity={complexity} "
                                   f"lockout={lockout_threshold}")
        return dict(rows)
