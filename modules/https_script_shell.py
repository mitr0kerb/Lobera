# modules/https_script_shell.py
import ast as _ast, importlib, inspect, sys
import pyfiglet
from pathlib import Path
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich import box
from core.output import console
from core.target import Target
from core.credentials import Creds
from scripts.base import BaseScript
from scripts.https.shell_params import SCRIPT_PARAMS, PARAM_LABELS  # ← https

COLOR    = "deep_sky_blue1"   
PROTOCOL = "https"            


def _build_family_map(root_path):
    family_map  = {}
    scripts_dir = root_path / "scripts" / PROTOCOL
    for py in sorted(scripts_dir.rglob("*.py")):
        if py.name in ("__init__.py","scanner.py","shell_params.py","scan_params.py"): continue
        family = py.parent.name
        if family in (PROTOCOL, "__pycache__"): continue
        try:
            source = py.read_text(encoding="utf-8", errors="replace")
            tree   = _ast.parse(source)
            for node in _ast.walk(tree):
                if isinstance(node, _ast.ClassDef) and node.bases:
                    for item in node.body:
                        if isinstance(item, _ast.Assign):
                            for t in item.targets:
                                if (isinstance(t, _ast.Name) and t.id == "name"
                                        and isinstance(item.value, _ast.Constant)):
                                    family_map[item.value.value] = family
        except Exception:
            continue
    return family_map

class HTTPSScriptShell:
    def __init__(self, root_path):
        self._root        = root_path if isinstance(root_path, Path) else Path(root_path)
        self._script_name = None
        self._params      = {}
        self._meta        = None
        self._family_map  = _build_family_map(self._root)

    def _banner(self):
        art = pyfiglet.figlet_format("HTTP", font="slant")
        console.print(f"[bold {COLOR}]{art}[/bold {COLOR}]", end="")
        console.print(Panel(
            f"[dim]Consola interactiva de scripts [bold {COLOR}]HTTP[/bold {COLOR}] — Lobera[/dim]\n"
            f"[dim]Escribe [bold]help[/bold] para ver los comandos disponibles.[/dim]",
            border_style=COLOR, expand=False))
        console.print()

    def _prompt(self):
        if self._script_name:
            return (f"[bold {COLOR}]http-shell[/bold {COLOR}]"
                    f"([bold white]{self._script_name}[/bold white]) > ")
        return f"[bold {COLOR}]http-shell[/bold {COLOR}] > "

    def run(self):
        self._banner()
        while True:
            try:
                line = console.input(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Saliendo de la consola HTTP.[/dim]"); break
            if not line: continue
            parts = line.split(maxsplit=2)
            cmd   = parts[0].lower()
            args  = parts[1:]
            if cmd in ("exit","quit"):
                console.print("[dim]Saliendo de la consola HTTP.[/dim]"); break
            elif cmd == "help":     self._cmd_help()
            elif cmd == "list":     self._cmd_list()
            elif cmd == "load":     self._cmd_load(args[0] if args else "")
            elif cmd == "load-fam": self._cmd_load_fam(args[0] if args else "")
            elif cmd == "set":      self._cmd_set(args[0] if args else "", args[1] if len(args)>1 else "")
            elif cmd == "unset":    self._cmd_unset(args[0] if args else "")
            elif cmd == "params":   self._cmd_params()
            elif cmd == "run":      self._cmd_run()
            elif cmd == "clear":    console.clear()
            else: console.print(f"[red]Comando desconocido: '{cmd}'[/red] — escribe [bold]help[/bold]")

    def _cmd_help(self):
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        t.add_column(style=f"bold {COLOR}"); t.add_column(style="dim")
        for cmd, desc in [
            ("list",           "Lista los scripts HTTPSS agrupados por familia"),
            ("load <script>",  "Carga un script individual"),
            ("load-fam <fam>", "Carga y ejecuta todos los scripts de una familia"),
            ("params",         "Muestra parámetros del script cargado"),
            ("set <k> <v>",    "Asigna un parámetro"),
            ("unset <k>",      "Elimina un parámetro"),
            ("run",            "Ejecuta el script cargado"),
            ("clear",          "Limpia la pantalla"),
            ("exit",           "Sale de la consola"),
        ]: t.add_row(cmd, desc)
        console.print(t)

    def _cmd_list(self):
        families = {}
        for name, meta in SCRIPT_PARAMS.items():
            fam = self._family_map.get(name, "other")
            families.setdefault(fam, []).append((name, meta["description"]))
        from rich.text import Text
        tree = Tree(f"[bold {COLOR}]HTTP[/bold {COLOR}]")
        for fam in sorted(families):
            branch = tree.add(f"[bold {COLOR}]{fam}[/bold {COLOR}]")
            for name, desc in sorted(families[fam]):
                label = Text(); label.append(name, style="bold white")
                label.append("  "); label.append(desc, style="dim")
                branch.add(label)
        console.print(tree)
        console.print(f"\n[dim]  load <script>       — carga un script[/dim]"
                      f"\n[dim]  load-fam <familia>  — ejecuta toda una familia[/dim]\n")

    def _cmd_load(self, name):
        if not name: console.print("[red]Uso: load <nombre-script>[/red]"); return
        if name not in SCRIPT_PARAMS:
            console.print(f"[red]Script '{name}' no reconocido.[/red] Usa [bold]list[/bold]."); return
        new_meta     = SCRIPT_PARAMS[name]
        new_defaults = new_meta.get("defaults", {})
        _PERSISTENT  = {"target","port","timeout","path"}
        new_params   = dict(new_defaults)
        for k, v in self._params.items():
            if k in _PERSISTENT and v not in (None, "", new_defaults.get(k)):
                new_params[k] = v
        self._script_name = name; self._meta = new_meta; self._params = new_params
        self._print_script_card()

    def _cmd_load_fam(self, family):
        if not family: console.print("[red]Uso: load-fam <familia>[/red]"); return
        scripts_in_fam = [n for n, f in self._family_map.items()
                          if f == family and n in SCRIPT_PARAMS]
        if not scripts_in_fam:
            available = sorted(set(self._family_map.values()))
            console.print(f"[red]Familia '{family}' no encontrada.[/red] "
                          f"Disponibles: {', '.join(available)}"); return
        console.print()
        console.print(Panel(
            f"[bold white]FAMILIA: {family.upper()}[/bold white]"
            f"  [dim]— módulo [bold {COLOR}]HTTP[/bold {COLOR}][/dim]\n\n"
            + "\n".join(f"  • {s}" for s in sorted(scripts_in_fam)),
            title=f"[bold {COLOR}]FAMILIA CARGADA[/bold {COLOR}]",
            border_style=COLOR, expand=False))
        console.print()
        all_required = None; all_optional = set()
        for name in scripts_in_fam:
            m       = SCRIPT_PARAMS[name]
            req_set = set(m.get("required",[])); opt_set = set(m.get("optional",[]))
            all_required = req_set if all_required is None else all_required & req_set
            all_optional.update(req_set | opt_set)
        all_required = all_required or set(); all_optional -= all_required
        shared_params = {}
        console.print("[bold]Parámetros compartidos:[/bold]")
        console.print("[dim](enter para omitir los opcionales)[/dim]\n")
        for p in sorted(all_required):
            label = PARAM_LABELS.get(p, p)
            while True:
                val = console.input(f"  [bold red]*[/bold red] {label} ({p}): ").strip()
                if val: shared_params[p] = val; break
                console.print(f"  [red]'{p}' es obligatorio.[/red]")
        for p in sorted(all_optional):
            label = PARAM_LABELS.get(p, p)
            val   = console.input(f"    {label} ({p}) [enter para omitir]: ").strip()
            if val: shared_params[p] = val
        console.print()
        target = Target(ip=shared_params.get("target",""), domain="",
                        timeout=int(shared_params.get("timeout",5)))
        creds  = Creds(user="", password="", domain="", hash=None)
        _base  = {"target","timeout"}
        extra  = self._cast_kwargs({k: v for k, v in shared_params.items() if k not in _base})
        for name in sorted(scripts_in_fam):
            console.rule(f"[bold {COLOR}]Ejecutando {name}[/bold {COLOR}]")
            py_path = self._find_script_path(name)
            if py_path is None:
                console.print(f"[yellow]Script '{name}' no encontrado — omitido.[/yellow]"); continue
            cls = self._import_script_cls(py_path)
            if cls is None: continue
            try: cls(target, creds).run(**extra)
            except KeyboardInterrupt: console.print("\n[dim]Script interrumpido.[/dim]")
            except Exception as e: console.print(f"[red]Error en '{name}': {e}[/red]")
            console.print()
        console.rule(f"[bold {COLOR}]Familia '{family}' completada[/bold {COLOR}]")
        console.print()

    def _cast_kwargs(self, kwargs):
        result = {}
        for k, v in kwargs.items():
            if k in ("port","timeout","max_depth","max_pages"):
                try: v = int(v)
                except (ValueError,TypeError): pass
            elif k == "delay":
                try: v = float(v)
                except (ValueError,TypeError): pass
            result[k] = v
        return result

    def _print_script_card(self):
        meta = self._meta; name = self._script_name
        fam  = self._family_map.get(name,"")
        console.print()
        console.print(Panel(
            f"[bold white]{name.upper()}[/bold white]"
            f"  [dim]— [bold {COLOR}]HTTP[/bold {COLOR}] / {fam}[/dim]\n\n{meta['description']}",
            title=f"[bold {COLOR}]SCRIPT CARGADO[/bold {COLOR}]",
            border_style=COLOR, expand=False))
        req  = meta.get("required",[]); opt = meta.get("optional",[]); defs = meta.get("defaults",{})
        t = Table(box=box.SIMPLE, show_header=True)
        t.add_column("Parámetro", style="bold"); t.add_column("Obligatorio", justify="center")
        t.add_column("Valor actual/default", style="cyan"); t.add_column("Descripción", style="dim")
        for p in req:
            t.add_row(p, "[bold red]✔[/bold red]",
                      str(self._params.get(p,"[vacío]")), PARAM_LABELS.get(p,""))
        for p in opt:
            default = str(defs.get(p,""))
            t.add_row(p, "", str(self._params.get(p, default or "[vacío]")),
                      PARAM_LABELS.get(p,""))
        console.print(t); console.print()
        console.print("  [bold]Ejemplo de uso:[/bold]")
        for line in meta.get("example",[]): console.print(f"    [dim]{line}[/dim]")
        console.print()

    def _cmd_set(self, key, value):
        if not key: console.print("[red]Uso: set <parámetro> <valor>[/red]"); return
        if not value: console.print(f"[red]Uso: set {key} <valor>[/red]"); return
        if key in ("port","timeout","max_depth","max_pages"):
            try: value = int(value)
            except ValueError: console.print(f"[red]{key} debe ser entero.[/red]"); return
        if key == "delay":
            try: value = float(value)
            except ValueError: console.print("[red]delay debe ser decimal.[/red]"); return
        self._params[key] = value
        console.print(f"  [bold {COLOR}]✓[/bold {COLOR}] {key} = [cyan]{value}[/cyan]")

    def _cmd_unset(self, key):
        if not key: console.print("[red]Uso: unset <parámetro>[/red]"); return
        if key in self._params:
            del self._params[key]; console.print(f"  [dim]{key} eliminado.[/dim]")
        else:
            console.print(f"  [dim]{key} no estaba definido.[/dim]")

    def _cmd_params(self):
        if not self._script_name:
            console.print("[yellow]No hay ningún script cargado.[/yellow]"); return
        self._print_script_card()

    def _cmd_run(self):
        if not self._script_name:
            console.print("[yellow]No hay script cargado. Usa [bold]load <script>[/bold].[/yellow]"); return
        meta    = self._meta
        missing = [p for p in meta.get("required",[]) if not self._params.get(p)]
        if missing:
            for p in missing:
                console.print(f"  [red]Falta: [bold]{p}[/bold][/red]\n  [dim]→ set {p} <valor>[/dim]")
            return
        target  = Target(ip=self._params.get("target",""), domain="",
                         timeout=int(self._params.get("timeout",5)))
        creds   = Creds(user="", password="", domain="", hash=None)
        py_path = self._find_script_path(self._script_name)
        if py_path is None:
            console.print(f"[red]No se encontró '{self._script_name}'.[/red]"); return
        cls = self._import_script_cls(py_path)
        if cls is None: return
        _base  = {"target","timeout"}
        kwargs = self._cast_kwargs({k: v for k, v in self._params.items() if k not in _base})
        console.print()
        console.rule(f"[bold {COLOR}]Ejecutando {self._script_name}[/bold {COLOR}]")
        try: cls(target, creds).run(**kwargs)
        except KeyboardInterrupt: console.print("\n[dim]Script interrumpido.[/dim]")
        except Exception as e: console.print(f"[red]Error: {e}[/red]")
        console.rule(f"[bold {COLOR}]Fin {self._script_name}[/bold {COLOR}]"); console.print()

    def _find_script_path(self, name):
        scripts_dir = self._root / "scripts" / PROTOCOL
        for py in sorted(scripts_dir.rglob("*.py")):
            if py.name in ("__init__.py","scanner.py","shell_params.py","scan_params.py"): continue
            if py.stem == name.replace("-","_") or py.stem == name: return py
            try:
                source = py.read_text(encoding="utf-8", errors="replace")
                tree   = _ast.parse(source)
                for node in _ast.walk(tree):
                    if isinstance(node, _ast.ClassDef) and node.bases:
                        for item in node.body:
                            if isinstance(item, _ast.Assign):
                                for t in item.targets:
                                    if (isinstance(t, _ast.Name) and t.id == "name"
                                            and isinstance(item.value, _ast.Constant)
                                            and item.value.value == name):
                                        return py
            except Exception: continue
        return None

    def _import_script_cls(self, py_path):
        root_str = str(self._root)
        if root_str not in sys.path: sys.path.insert(0, root_str)
        rel      = py_path.relative_to(self._root)
        mod_path = str(rel).replace("/",".").replace("\\",".")[:-3]
        try: mod = importlib.import_module(mod_path)
        except Exception as e:
            console.print(f"[red]Error importando: {e}[/red]"); return None
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if obj is not BaseScript and issubclass(obj, BaseScript): return obj
        console.print("[red]No se encontró clase de script.[/red]"); return None
