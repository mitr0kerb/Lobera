
# scripts/smb/post/task_list.py
"""Enumerate scheduled tasks on the remote host via TSCH pipe."""
from core.output import console, print_result, print_table
from core import session_db
from scripts.base import BaseScript

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, tsch
    _OK = True
except ImportError:
    _OK = False


class Script(BaseScript):
    name        = "task-list"
    protocol    = "smb"
    category    = "post"
    description = "List scheduled tasks on the remote host via TSCH pipe. Requires admin."

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

        tasks = []
        try:
            conn = SMBConnection(ip, ip, timeout=timeout)
            conn.login(user, passwd, domain, lm_hash, nt_hash)
            rpctransport = transport.SMBTransport(ip, filename="\\\\atsvc", smb_connection=conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(tsch.MSRPC_UUID_TSCHS)

            resp = tsch.hSchRpcEnumTasks(dce, "\\")
            for task in resp["pNames"]:
                tname = str(task).strip("\x00")
                if tname:
                    tasks.append((tname,))
                    session_db.DB.SaveFinding(ip, "SMB", "scheduled_task", f"task={tname}")

            dce.disconnect(); conn.logoff()
        except Exception as e:
            print_result("SMB", ip, "fail", f"TSCH error: {e}"); return None

        if tasks:
            print_table(f"Scheduled tasks on {ip}", ["Task Name"], tasks)
            print_result("SMB", ip, "ok", f"{len(tasks)} task(s) found")
        else:
            print_result("SMB", ip, "info", "No scheduled tasks found (or access denied)")
        return tasks
