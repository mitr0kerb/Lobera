# scripts/mssql/enum/db_enum.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_check, print_table
from core import session_db

SENSITIVE = ["password","passwd","pwd","secret","token","hash","cred","apikey","api_key"]

class Script(BaseScript):
    name        = "db-enum"
    protocol    = "mssql"
    category    = "enum"
    description = "Enumera bases de datos accesibles y columnas sensibles (passwords, tokens...)."

    def run(self, **kwargs):
        port = int(kwargs.get("port") or 1433)
        mod  = MSSQLModule(self.target, self.creds)
        if not mod.connect(port=port):
            return None
        if not mod.login():
            mod.disconnect(); return None
        try:
            dbs  = mod.list_databases()
            hits = []
            for db in dbs:
                if db in ("master","tempdb","model","msdb"):
                    continue
                like_clauses = " OR ".join(
                    "LOWER(COLUMN_NAME) LIKE '%" + p + "%'" for p in SENSITIVE
                )
                rows = mod.query(
                    "SELECT TABLE_SCHEMA+'.'+TABLE_NAME AS tbl, COLUMN_NAME "
                    "FROM [" + db + "].INFORMATION_SCHEMA.COLUMNS "
                    "WHERE " + like_clauses,
                    silent=True
                )
                for r in (rows or []):
                    hits.append((db, r.get("tbl","?"), r.get("COLUMN_NAME","?")))
                    session_db.save_finding(self.target.ip, "MSSQL", "sensitive_column",
                                           db + "." + r.get("tbl","?") + "." + r.get("COLUMN_NAME","?"))
            if hits:
                print_table("Columnas sensibles en " + self.target.ip,
                            ["DB","Tabla","Columna"], hits)
                print_check(str(len(hits)) + " columna(s) sensible(s) encontrada(s)", ok=False)
            else:
                print_check("Sin columnas sensibles detectadas en DBs de usuario", ok=True)
            return {"databases": dbs, "sensitive_columns": hits}
        finally:
            mod.disconnect()
