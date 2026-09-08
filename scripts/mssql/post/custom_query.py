# scripts/mssql/post/custom_query.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_result, print_table

class Script(BaseScript):
    name        = "custom-query"
    protocol    = "mssql"
    category    = "post"
    description = "Ejecuta una query SQL arbitraria y muestra el resultado formateado."

    def run(self, **kwargs):
        query = kwargs.get("query", "")
        port  = int(kwargs.get("port") or 1433)
        if not query:
            print_result("MSSQL", self.target.ip, "fail", "query no especificada")
            return None
        mod = MSSQLModule(self.target, self.creds)
        if not mod.connect(port=port):
            return None
        if not mod.login():
            mod.disconnect(); return None
        try:
            rows = mod.query(query)
            if rows:
                headers    = list(rows[0].keys()) if rows else ["resultado"]
                table_rows = [tuple(str(v) for v in r.values()) for r in rows]
                print_table("Query en " + self.target.ip, headers, table_rows)
                print_result("MSSQL", self.target.ip, "info",
                             str(len(rows)) + " fila(s) devuelta(s)")
            return rows
        finally:
            mod.disconnect()
