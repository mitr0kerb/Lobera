# modules/classic.py
"""
Modo clasico de Lobera — sin prompts interactivos.

Flujo:
  python3 lobera.py smb
      -> lista scripts del protocolo agrupados por familia

  python3 lobera.py smb --script=null-session
      -> muestra parametros requeridos y opcionales con ejemplos de uso

  python3 lobera.py smb --script=null-session -t 10.10.10.5
      -> si faltan obligatorios: avisa. Si estan todos: ejecuta.

  python3 lobera.py smb --script-fam=enum -t 10.10.10.5
      -> ejecuta todos los scripts de la familia con los params dados
"""

import ast as _ast
import importlib
import inspect
import sys
from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich import box

from core.output import console
from core.target import Target
from core.credentials import Creds
from scripts.base import BaseScript


# ── discovery ─────────────────────────────────────────────────────────────────

def _iter_scripts(scripts_dir):
    for py in sorted(scripts_dir.rglob("*.py")):
        if py.name in ("__init__.py", "scanner.py",
                       "shell_params.py", "scan_params.py"):
            continue
        if py.parent.name == "__pycache__":
            continue
        yield py


def _extract_meta(py_path):
    proto  = py_path.parents[1].name
    family = py_path.parent.name
    if family == proto:
        return None
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
        tree   = _ast.parse(source)
    except Exception:
        return None
    name = desc = None
    for node in _ast.walk(tree):
        if not (isinstance(node, _ast.ClassDef) and node.bases):
            continue
        for item in node.body:
            if not isinstance(item, _ast.Assign):
                continue
            for t in item.targets:
                if not isinstance(t, _ast.Name):
                    continue
                if t.id == "name" and isinstance(item.value, _ast.Constant):
                    name = item.value.value
                if t.id == "description" and isinstance(item.value, _ast.Constant):
                    desc = item.value.value
    if name is None:
        return None
    return {"name": name, "family": family, "description": desc or "", "path": py_path}


def _build_registry(protocol, root_path):
    scripts_dir = root_path / "scripts" / protocol
    if not scripts_dir.exists():
        return {}
    registry = {}
    for py in _iter_scripts(scripts_dir):
        meta = _extract_meta(py)
        if meta:
            registry[meta["name"]] = meta
    return registry


def _load_shell_params(protocol, root_path):
    sp_path = root_path / "scripts" / protocol / "shell_params.py"
    if not sp_path.exists():
        return {}, {}
    root_str = str(root_path)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    mod_path = "scripts." + protocol + ".shell_params"
    try:
        mod = importlib.import_module(mod_path)
        return getattr(mod, "SCRIPT_PARAMS", {}), getattr(mod, "PARAM_LABELS", {})
    except Exception:
        return {}, {}


def _import_cls(py_path, root_path):
    root_str = str(root_path)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    rel      = py_path.relative_to(root_path)
    mod_path = str(rel).replace("/", ".").replace("\\", ".")[:-3]
    try:
        mod = importlib.import_module(mod_path)
    except Exception as e:
        console.print("[red]Error importando script: " + str(e) + "[/red]")
        return None
    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if obj is not BaseScript and issubclass(obj, BaseScript):
            return obj
    return None


# ── obtener valor de param desde args ────────────────────────────────────────

_PARAM_TO_ARG = {
    "target":              "target",
    "user":                "user",
    "password":            "password",
    "hash":                "hash",
    "domain":              "domain",
    "timeout":             "timeout",
    "port":                "port",
    "instance":            "instance",
    "ldaps":               "ldaps",
    "ssl":                 "ssl",
    "sni":                 "sni",
    "http_port":           "http_port",
    "userlist":            "userlist",
    "passlist":            "passlist",
    "wordlist":            "wordlist",
    "delay":               "delay",
    "share":               "share",
    "ext":                 "ext",
    "keywords":            "keywords",
    "depth":               "depth",
    "spn":                 "spn",
    "ccache":              "ccache",
    "kirbi":               "kirbi",
    "krbtgt_hash":         "krbtgt_hash",
    "service_hash":        "service_hash",
    "domain_sid":          "domain_sid",
    "user_id":             "user_id",
    "groups":              "groups",
    "target_user":         "target_user",
    "target_computer":     "target_computer",
    "attacker_account":    "attacker_account",
    "cert":                "cert",
    "pfx":                 "pfx",
    "template":            "template",
    "ca":                  "ca",
    "alt_name":            "alt_name",
    "dc_name":             "dc_name",
    "user_sid":            "user_sid",
    "vector":              "vector",
    "new_password":        "new_password",
    "target_dn":           "target_dn",
    "target_obj":          "target_obj",
    "out_dir":             "out_dir",
    "save_list":           "save_list",
    "filter_flag":         "filter_flag",
    "enabled_only":        "enabled_only",
    "privileged_only":     "privileged_only",
    "os_filter":           "os_filter",
    "undeleg":             "undeleg",
    "action":              "action",
    "source_user":         "source_user",
    "save_key":            "save_key",
    "mode":                "mode",
    "relay_target_user":   "relay_target_user",
    "continue_on_lockout": "continue_on_lockout",
    "command":             "command",
    "query":               "query",
    "attacker_ip":         "attacker_ip",
    "path":                "path",
    "param":               "param",
    "listener":            "listener",
    "client_id":           "client_id",
    "max_depth":           "max_depth",
    "max_pages":           "max_pages",
}


def _get_param_value(param_name, args):
    arg_name = _PARAM_TO_ARG.get(param_name, param_name)
    return getattr(args, arg_name, None)


def _build_target_creds(args):
    target = Target(
        ip=getattr(args, "target", "") or "",
        domain=getattr(args, "domain", "") or "",
        timeout=int(getattr(args, "timeout", None) or 5),
    )
    creds = Creds(
        user=getattr(args, "user", "") or "",
        password=getattr(args, "password", "") or "",
        domain=getattr(args, "domain", "") or "",
        hash=getattr(args, "hash", None),
    )
    return target, creds


def _cast_extra_kwargs(meta, args):
    _base = {"target", "domain", "timeout", "user", "password", "hash"}
    req = set(meta.get("required", []))
    opt = set(meta.get("optional", []))
    kwargs = {}
    for p in (req | opt):
        if p in _base:
            continue
        val = _get_param_value(p, args)
        if val is None:
            continue
        if p in ("port", "depth", "timeout", "user_id",
                 "max_depth", "max_pages", "http_port"):
            try: val = int(val)
            except (ValueError, TypeError): pass
        if p == "delay":
            try: val = float(val)
            except (ValueError, TypeError): pass
        if p in ("ldaps", "ssl", "enabled_only", "privileged_only",
                 "undeleg", "continue_on_lockout"):
            if isinstance(val, str):
                val = val.lower() in ("true", "1", "yes")
        kwargs[p] = val
    return kwargs


# ── listado de scripts ────────────────────────────────────────────────────────

def list_scripts(protocol, root_path, color="white"):
    registry = _build_registry(protocol, root_path)
    if not registry:
        console.print("[yellow]No se encontraron scripts para '" + protocol + "'.[/yellow]")
        return

    families = {}
    for meta in registry.values():
        families.setdefault(meta["family"], []).append(meta)

    tree = Tree("[bold " + color + "]" + protocol.upper() + "[/bold " + color + "]")
    for fam in sorted(families):
        branch = tree.add("[bold " + color + "]" + fam + "[/bold " + color + "]")
        for meta in sorted(families[fam], key=lambda m: m["name"]):
            from rich.text import Text
            label = Text()
            label.append(meta["name"], style="bold white")
            label.append("  ")
            label.append(meta["description"][:72], style="dim")
            branch.add(label)
    console.print(tree)
    console.print()
    console.print("  [dim]--script=<nombre>             ejecuta un script[/dim]")
    console.print("  [dim]--script-fam=<familia>        ejecuta toda una familia[/dim]")
    console.print("  [dim]--interactive-shell            consola interactiva[/dim]")
    console.print("  [dim]--scanner                      autopwn scanner[/dim]")
    console.print()


# ── mostrar parametros / ejecutar ─────────────────────────────────────────────

def _show_params(protocol, script_name, sp_meta, param_labels, color, args):
    """
    Muestra los parametros requeridos y opcionales.
    Devuelve la lista de obligatorios que faltan.
    """
    req  = sp_meta.get("required", [])
    opt  = sp_meta.get("optional", [])
    defs = sp_meta.get("defaults", {})

    missing_req = [p for p in req if not _get_param_value(p, args)]

    console.print()
    console.print(Panel(
        "[bold white]" + script_name.upper() + "[/bold white]"
        "  [dim]— [bold " + color + "]" + protocol.upper()
        + "[/bold " + color + "] / " + sp_meta.get("family", "") + "[/dim]\n\n"
        + sp_meta.get("description", ""),
        title="[bold " + color + "]SCRIPT[/bold " + color + "]",
        border_style=color, expand=False,
    ))

    if req:
        console.print("[bold]PARÁMETROS REQUERIDOS[/bold]\n")
        for p in req:
            label   = param_labels.get(p, p)
            default = defs.get(p, "")
            val     = _get_param_value(p, args)
            given   = val is not None and val != "" and val is not False
            flag    = "--" + p.replace("_", "-") if len(p) > 1 else "-" + p
            if given:
                console.print(
                    "  [bold green]✓[/bold green]  "
                    + flag + " [cyan]" + str(val) + "[/cyan]"
                    + "  [dim](" + label + ")[/dim]"
                )
            else:
                default_str = (
                    "  [dim](default: " + str(default) + ")[/dim]"
                    if default not in (None, "") else ""
                )
                console.print(
                    "  [bold red]*[/bold red]  "
                    + flag + " <valor>"
                    + default_str
                    + "  [dim](" + label + ")[/dim]"
                )
        console.print()

    if opt:
        console.print("[bold]PARÁMETROS OPCIONALES[/bold]\n")
        for p in opt:
            label   = param_labels.get(p, p)
            default = defs.get(p, "")
            val     = _get_param_value(p, args)
            given   = val is not None and val != "" and val is not False
            flag    = "--" + p.replace("_", "-")
            default_str = (
                "  [dim](default: " + str(default) + ")[/dim]"
                if default not in (None, "") else ""
            )
            if given:
                console.print(
                    "  [bold green]✓[/bold green]  "
                    + flag + " [cyan]" + str(val) + "[/cyan]"
                    + default_str
                    + "  [dim](" + label + ")[/dim]"
                )
            else:
                console.print(
                    "  [dim]·[/dim]  "
                    + flag + " <valor>"
                    + default_str
                    + "  [dim](" + label + ")[/dim]"
                )
        console.print()

    for group in sp_meta.get("mutually_exclusive", []):
        console.print(
            "  [yellow]⚠[/yellow]  [dim]"
            + " y ".join(group) + " son mutuamente excluyentes.[/dim]"
        )

    # Ejemplo de uso
    console.print("[bold]EJEMPLO DE USO[/bold]\n")
    example_req = " ".join(
        "--" + p.replace("_", "-") + " <" + p + ">"
        for p in req
    )
    console.print(
        "  [dim]python3 lobera.py " + protocol
        + " --script=" + script_name
        + (" " + example_req if example_req else "")
        + "[/dim]"
    )
    console.print()

    if missing_req:
        console.print(
            "[red]Faltan parámetros obligatorios:[/red] "
            + ", ".join("[bold]--" + p.replace("_", "-") + "[/bold]" for p in missing_req)
        )
        console.print("[dim]Añádelos al comando y vuelve a ejecutar.[/dim]\n")

    return missing_req


# ── run_script ────────────────────────────────────────────────────────────────

def run_script(protocol, script_name, root_path, color="white", args=None):
    """
    python3 lobera.py <proto> --script=<nombre> [params...]

    Sin params suficientes: muestra la ayuda de parametros y sale.
    Con todos los obligatorios: ejecuta directamente.
    """
    registry                   = _build_registry(protocol, root_path)
    shell_params, param_labels = _load_shell_params(protocol, root_path)

    meta_disc = (
        registry.get(script_name)
        or registry.get(script_name.replace("-", "_"))
    )
    if not meta_disc:
        console.print(
            "[red]Script '" + script_name
            + "' no encontrado para '" + protocol + "'.[/red]"
        )
        console.print(
            "  [dim]Usa: python3 lobera.py " + protocol
            + "  para ver los disponibles.[/dim]"
        )
        return

    sp_meta = dict(shell_params.get(script_name, {}))
    sp_meta["family"]      = meta_disc["family"]
    sp_meta["description"] = sp_meta.get("description") or meta_disc["description"]

    if args is None:
        # Sin args: solo mostrar params sin marcar nada
        import argparse
        args = argparse.Namespace()

    missing = _show_params(protocol, script_name, sp_meta, param_labels, color, args)

    if missing:
        return  # Faltan obligatorios, no ejecutar

    # Todos presentes: ejecutar
    target, creds = _build_target_creds(args)
    kwargs        = _cast_extra_kwargs(sp_meta, args)

    cls = _import_cls(meta_disc["path"], root_path)
    if cls is None:
        console.print("[red]No se pudo cargar el script.[/red]")
        return

    console.rule("[bold " + color + "]Ejecutando " + script_name + "[/bold " + color + "]")
    try:
        cls(target, creds).run(**kwargs)
    except KeyboardInterrupt:
        console.print("\n[dim]Script interrumpido.[/dim]")
    except Exception as e:
        console.print("[red]Error: " + str(e) + "[/red]")
    console.rule("[bold " + color + "]Fin " + script_name + "[/bold " + color + "]")
    console.print()


# ── run_script_family ─────────────────────────────────────────────────────────

def run_script_family(protocol, family, root_path, color="white", args=None):
    """
    python3 lobera.py <proto> --script-fam=<familia> [params...]
    """
    registry                   = _build_registry(protocol, root_path)
    shell_params, param_labels = _load_shell_params(protocol, root_path)

    scripts_in_fam = [m for m in registry.values() if m["family"] == family]
    if not scripts_in_fam:
        available = sorted({m["family"] for m in registry.values()})
        console.print(
            "[red]Familia '" + family
            + "' no encontrada para '" + protocol + "'.[/red]"
        )
        console.print("  Familias disponibles: " + ", ".join(available))
        return

    console.print()
    console.print(Panel(
        "[bold white]FAMILIA: " + family.upper() + "[/bold white]"
        "  [dim]— [bold " + color + "]" + protocol.upper()
        + "[/bold " + color + "][/dim]\n\n"
        + "\n".join(
            "  • " + m["name"]
            for m in sorted(scripts_in_fam, key=lambda m: m["name"])
        ),
        title="[bold " + color + "]EJECUTANDO FAMILIA[/bold " + color + "]",
        border_style=color, expand=False,
    ))
    console.print()

    if args is None:
        import argparse
        args = argparse.Namespace()

    target, creds = _build_target_creds(args)

    for m in sorted(scripts_in_fam, key=lambda m: m["name"]):
        sp_meta = dict(shell_params.get(m["name"], {}))
        sp_meta["family"] = m["family"]

        req     = sp_meta.get("required", [])
        missing = [p for p in req if not _get_param_value(p, args)]
        if missing:
            console.print(
                "[yellow]" + m["name"]
                + " — omitido, faltan: " + ", ".join(missing) + "[/yellow]"
            )
            continue

        kwargs = _cast_extra_kwargs(sp_meta, args)
        cls    = _import_cls(m["path"], root_path)
        if cls is None:
            console.print("[yellow]" + m["name"] + " — no se pudo cargar.[/yellow]")
            continue

        console.rule(
            "[bold " + color + "]Ejecutando " + m["name"] + "[/bold " + color + "]"
        )
        try:
            cls(target, creds).run(**kwargs)
        except KeyboardInterrupt:
            console.print("\n[dim]Script interrumpido.[/dim]")
        except Exception as e:
            console.print("[red]Error en '" + m["name"] + "': " + str(e) + "[/red]")
        console.print()

    console.rule(
        "[bold " + color + "]Familia '" + family + "' completada[/bold " + color + "]"
    )
    console.print()
