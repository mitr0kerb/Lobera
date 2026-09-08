# core/scanner.py

import json
import os
from datetime import datetime
from xml.etree import ElementTree as ET

from rich.table import Table
from rich import box

from core.output import console
from core import session_db


EXPORT_FORMATS = ["json", "html", "xml", "yaml"]


def _get_script_cls(protocol, script_name):
    """
    Busca la clase de un script usando el loader existente.
    Devuelve la clase o None si no se encuentra.
    """
    from scripts.loader import discover_scripts
    registry = discover_scripts(protocol=protocol)
    return registry.get(script_name)


class ScanStep:
    """Representa un paso del scan: un script + su condición de ejecución."""

    def __init__(self, script_name, condition=None):
        self.script_name = script_name
        self.condition   = condition

    def should_run(self, ctx):
        if self.condition is None:
            return True
        evaluator = getattr(ctx, f"_cond_{self.condition}", None)
        if evaluator is None:
            return False
        return evaluator()


class ScanContext:
    """
    Estado acumulado durante el scan.
    Los evaluadores de condición leen de aquí para decidir
    si lanzar el siguiente script.
    """

    def __init__(self, params):
        self.params   = params
        self.findings = []
        self.results  = {}
        self.actions  = []

    # ── Evaluadores de condición ──────────────────────────────────────────────

    def _cond_has_auth(self):
        """True si hay credenciales reales (no null session)."""
        p = self.params
        return bool(p.get("user")) and (bool(p.get("password")) or bool(p.get("hash")))

    def _cond_has_shares(self):
        """True si shares encontró al menos un share no especial."""
        result = self.results.get("shares", [])
        if not result:
            return False
        return any("special" not in str(r[1]).lower() for r in result)

    def _cond_has_userlist(self):
        """True si se proporcionó un fichero de usuarios válido."""
        ul = self.params.get("userlist")
        return bool(ul) and os.path.isfile(str(ul))

    def _cond_null_ok(self):
        """True si null-session está permitida en el objetivo."""
        return any(
            f.get("finding_type") == "null_session"
            for f in self.findings
        )

    def refresh_findings(self, target_ip):
        """Sincroniza findings desde session_db tras cada script."""
        self.findings = session_db.get_findings(target_ip)


class Scanner:
    """Motor genérico de scan automático."""

    VERBOSE_LABELS = {
        1: "Básico — solo hallazgos críticos",
        2: "Normal — hallazgos + acciones tomadas",
        3: "Debug — todo el output de cada script",
    }

    def __init__(self, target, creds, steps, protocol, color,
                 verbose, save_to_db, export_path=None, export_fmt=None):
        self.target      = target
        self.creds       = creds
        self.steps       = steps
        self.protocol    = protocol
        self.color       = color
        self.verbose     = verbose
        self.save_to_db  = save_to_db
        self.export_path = export_path
        self.export_fmt  = export_fmt
        self.ctx         = ScanContext({})

    # ── Helpers visuales ──────────────────────────────────────────────────────

    def _section(self, title):
        console.rule(f"[bold {self.color}]{title}[/bold {self.color}]")

    def _ok(self, msg):
        if self.verbose >= 2:
            console.print(f"  [bold green]✓[/bold green] {msg}")

    def _info(self, msg):
        if self.verbose >= 2:
            console.print(f"  [bold blue]ℹ[/bold blue]  {msg}")

    def _warn(self, msg):
        console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")

    def _critical(self, msg):
        console.print(f"  [bold red]✘ CRÍTICO:[/bold red] {msg}")

    def _debug(self, msg):
        if self.verbose >= 3:
            console.print(f"  [dim]{msg}[/dim]")

    # ── Ejecución ─────────────────────────────────────────────────────────────

    def run(self):
        self._section("Iniciando scan")
        total = len(self.steps)

        for i, step in enumerate(self.steps, 1):
            self.ctx.refresh_findings(self.target.ip)

            if not step.should_run(self.ctx):
                self._debug(f"[{i}/{total}] {step.script_name} — omitido (condición no cumplida)")
                continue

            self._section(f"[{i}/{total}] {step.script_name}")

            script_cls = _get_script_cls(self.protocol.lower(), step.script_name)
            if script_cls is None:
                self._warn(f"Script '{step.script_name}' no encontrado en '{self.protocol.lower()}' — omitido")
                continue

            try:
                script = script_cls(self.target, self.creds)
                kwargs = self._build_kwargs(step.script_name)

                if self.verbose < 3:
                    kwargs["silent"] = True

                result = script.run(**kwargs)
                self.ctx.results[step.script_name] = result
                self.ctx.actions.append({
                    "script":         step.script_name,
                    "timestamp":      datetime.now().isoformat(),
                    "result_summary": self._summarize(step.script_name, result),
                })
                self._on_result(step.script_name, result)

            except Exception as e:
                self._warn(f"Error en '{step.script_name}': {e}")
                self.ctx.results[step.script_name] = None

        self.ctx.refresh_findings(self.target.ip)
        self._print_summary()

        if self.export_path:
            self._export()

    def _build_kwargs(self, script_name):
        """Mapea parámetros del contexto a kwargs de cada script."""
        p = self.ctx.params
        base = {
            "user":     p.get("user", ""),
            "password": p.get("password", ""),
            "hash":     p.get("hash"),
            "domain":   p.get("domain", ""),
        }
        extras = {
            "password-spray": {"userlist": p.get("userlist"), "password": p.get("password", "")},
            "spider":         {"depth": 5, "keywords": None},
        }
        base.update(extras.get(script_name, {}))
        return base

    def _summarize(self, script_name, result):
        if result is None:
            return "sin resultado"
        if isinstance(result, list):
            return f"{len(result)} elemento(s)"
        if isinstance(result, bool):
            return "sí" if result else "no"
        return str(result)[:80]

    # ── Handlers de resultado por script ──────────────────────────────────────

    def _on_result(self, script_name, result):
        handlers = {
            "signing-check":  self._on_signing,
            "null-session":   self._on_null_session,
            "shares":         self._on_shares,
            "gpp-password":   self._on_gpp,
            "spider":         self._on_spider,
            "password-spray": self._on_spray,
        }
        handler = handlers.get(script_name)
        if handler:
            handler(result)

    def _on_signing(self, result):
        if result is False:
            self._critical("SMB signing NO obligatorio → vulnerable a NTLM relay")
        elif result is True:
            self._ok("SMB signing obligatorio (protegido)")

    def _on_null_session(self, result):
        if result is True:
            self._critical("Null session permitida → enumeración sin credenciales posible")
        else:
            self._ok("Null session denegada")

    def _on_shares(self, result):
        if not result:
            self._info("No se encontraron shares accesibles")
            return
        non_special = [
            r for r in result
            if isinstance(r, (list, tuple)) and len(r) >= 2
            and "special" not in str(r[1]).lower()
        ]
        self._ok(f"{len(result)} share(s) encontrados, {len(non_special)} no especiales")
        for row in result:
            if isinstance(row, (list, tuple)) and len(row) >= 2:
                self._debug(f"    {str(row[0]):20s} {str(row[1]):20s}")

    def _on_gpp(self, result):
        if result:
            self._critical(f"GPP credentials encontradas: {len(result)} fichero(s) — MS14-025")
        else:
            self._ok("GPP: sin credenciales encontradas")

    def _on_spider(self, result):
        if result:
            self._critical(f"Spider: {len(result)} fichero(s) descargados en loot/")
        else:
            self._ok("Spider: sin ficheros de interés encontrados")

    def _on_spray(self, result):
        if result:
            self._critical(f"Password spray: {len(result)} credencial(es) válida(s) → {result}")
        else:
            self._ok("Password spray: ninguna credencial válida")

    # ── Resumen final ─────────────────────────────────────────────────────────

    def _print_summary(self):
        self._section("Resumen del scan")

        table = Table(box=box.ROUNDED, border_style=self.color, show_header=True)
        table.add_column("Script",    style="bold")
        table.add_column("Resultado")
        table.add_column("Crítico",   justify="center")

        critical_scripts = {"signing-check", "null-session", "gpp-password", "password-spray"}

        for step in self.steps:
            result  = self.ctx.results.get(step.script_name)
            if step.script_name not in self.ctx.results:
                summary = "[dim]omitido[/dim]"
                is_crit = ""
            else:
                summary = self._summarize(step.script_name, result)
                is_crit = "🔴" if step.script_name in critical_scripts and result else ""
            table.add_row(step.script_name, summary, is_crit)

        console.print(table)
        console.print()

    # ── Export ────────────────────────────────────────────────────────────────

    def _export(self):
        fmt  = self.export_fmt
        path = self.export_path

        data = {
            "scan_date":   datetime.now().isoformat(),
            "target":      self.target.ip,
            "protocol":    self.protocol,
            "verbose":     self.verbose,
            "findings":    self.ctx.findings,
            "actions":     self.ctx.actions,
            "results":     {k: self._summarize(k, v) for k, v in self.ctx.results.items()},
            "credentials": session_db.get_credentials(self.target.ip, only_valid=False),
        }

        try:
            if fmt == "json":
                with open(path, "w") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

            elif fmt == "yaml":
                import yaml
                with open(path, "w") as f:
                    yaml.dump(data, f, allow_unicode=True, default_flow_style=False)

            elif fmt == "xml":
                root = ET.Element("lobera_scan")
                for key, val in data.items():
                    child = ET.SubElement(root, key)
                    child.text = (
                        json.dumps(val, ensure_ascii=False)
                        if not isinstance(val, str)
                        else val
                    )
                ET.indent(root)
                tree = ET.ElementTree(root)
                tree.write(path, encoding="unicode", xml_declaration=True)

            elif fmt == "html":
                self._export_html(data, path)

            console.print(f"\n[bold green]✓[/bold green] Resultados exportados → [cyan]{path}[/cyan]")

        except Exception as e:
            console.print(f"[red]Error exportando resultados: {e}[/red]")

    def _export_html(self, data, path):
        findings_rows = "".join(
            f"<tr><td>{f.get('protocol','')}</td><td>{f.get('finding_type','')}</td>"
            f"<td>{f.get('detail','')}</td><td>{f.get('timestamp','')}</td></tr>"
            for f in data["findings"]
        )
        actions_rows = "".join(
            f"<tr><td>{a.get('script','')}</td><td>{a.get('result_summary','')}</td>"
            f"<td>{a.get('timestamp','')}</td></tr>"
            for a in data["actions"]
        )
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Lobera Scan — {data['target']}</title>
  <style>
    body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
    h1 {{ color: #58a6ff; }}
    h2 {{ color: #3fb950; border-bottom: 1px solid #30363d; padding-bottom: .3rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
    th {{ background: #161b22; color: #58a6ff; padding: .5rem 1rem; text-align: left; }}
    td {{ padding: .4rem 1rem; border-bottom: 1px solid #21262d; }}
    tr:hover td {{ background: #161b22; }}
    .meta {{ color: #8b949e; font-size: .9rem; margin-bottom: 2rem; }}
  </style>
</head>
<body>
  <h1>🐺 Lobera Scan Report</h1>
  <p class="meta">
    Target: <strong>{data['target']}</strong> &nbsp;|&nbsp;
    Protocolo: <strong>{data['protocol']}</strong> &nbsp;|&nbsp;
    Fecha: {data['scan_date']}
  </p>
  <h2>Hallazgos</h2>
  <table>
    <tr><th>Protocolo</th><th>Tipo</th><th>Detalle</th><th>Timestamp</th></tr>
    {findings_rows or '<tr><td colspan="4">Sin hallazgos</td></tr>'}
  </table>
  <h2>Acciones</h2>
  <table>
    <tr><th>Script</th><th>Resultado</th><th>Timestamp</th></tr>
    {actions_rows or '<tr><td colspan="3">Sin acciones</td></tr>'}
  </table>
</body>
</html>"""
        with open(path, "w") as f:
            f.write(html)
