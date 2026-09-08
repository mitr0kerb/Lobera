
# scripts/smb/post/service_list.py
"""List services on the remote host via SVCCTL pipe."""
from core.output import console, print_result, print_table
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, scmr
    _OK = True
except ImportError:
    _OK = False

_STATES = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING",
           4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED"}


class Script(BaseScript):
    name        = "service-list"
    protocol    = "smb"
    category    = "post"
    description = "List Windows services on the remote host via SVCCTL pipe. Requires admin."

    def run(self, **kwargs):
        if not _OK:
            console.print("[red]impacket not installed.[/red]"); return None

        ip       = self.target.ip
        domain   = self.creds.domain   or ""
        user     = self.creds.user     or ""
        passwd   = self.creds.password or ""
        nt_hash  = self.creds.hash     or ""
        timeout  = self.target.timeout or 5
        running_only = bool(kwargs.get("running_only", False))

        lm_hash = ""
        if nt_hash and ":" in nt_hash:
            lm_hash, nt_hash = nt_hash.split(":", 1)

        services = []
        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
            rpctransport = transport.SMBTransport(
                ip, filename="\\\\svcctl", smb_connection=conn
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)

            scm_handle = scmr.hROpenSCManagerW(dce)["lpScHandle"]
            resp = scmr.hREnumServicesStatusW(
                dce, scm_handle,
                dwServiceType=scmr.SERVICE_WIN32_OWN_PROCESS | scmr.SERVICE_WIN32_SHARE_PROCESS,
                dwServiceState=scmr.SERVICE_STATE_ALL,
            )
            for svc in resp:
                name    = str(svc["lpServiceName"]).strip("\x00")
                display = str(svc["lpDisplayName"]).strip("\x00")
                state   = _STATES.get(svc["ServiceStatus"]["dwCurrentState"], "UNKNOWN")
                if running_only and state != "RUNNING":
                    continue
                services.append((name, display, state))
                if state == "RUNNING":
                    session_db.DB.SaveFinding(ip, "SMB", "service_running",
                                               f"name={name} display={display}")

            scmr.hRCloseServiceHandle(dce, scm_handle)
            dce.disconnect(); conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"SVCCTL error: {e}"); return None

        if services:
            print_table(f"Services on {ip}", ["Name", "Display Name", "State"], services)
            running = sum(1 for s in services if s[2] == "RUNNING")
            print_result("SMB", ip, "ok",
                         f"{len(services)} service(s) found ({running} running)")
        else:
            print_result("SMB", ip, "info", "No services found (or access denied)")
        return services
