# modules/classic.py
"""
Modo clasico de Lobera — sin prompts interactivos.
Todos los strings de UI pasan por T() para soporte i18n.
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
from core.i18n import T, TLabel
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
        console.print(f"[red]{T('import_error')}: {e}[/red]")
        return None
    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if obj is not BaseScript and issubclass(obj, BaseScript):
            return obj
    return None


# ── obtener valor de param desde args ────────────────────────────────────────

_PARAM_TO_ARG = {
    "target": "target", "user": "user", "password": "password",
    "hash": "hash", "domain": "domain", "timeout": "timeout",
    "port": "port", "instance": "instance", "ldaps": "ldaps",
    "ssl": "ssl", "sni": "sni", "http_port": "http_port",
    "userlist": "userlist", "passlist": "passlist", "wordlist": "wordlist",
    "delay": "delay", "share": "share", "ext": "ext",
    "keywords": "keywords", "depth": "depth", "spn": "spn",
    "ccache": "ccache", "kirbi": "kirbi", "krbtgt_hash": "krbtgt_hash",
    "service_hash": "service_hash", "domain_sid": "domain_sid",
    "user_id": "user_id", "groups": "groups", "target_user": "target_user",
    "target_computer": "target_computer", "attacker_account": "attacker_account",
    "cert": "cert", "pfx": "pfx", "template": "template", "ca": "ca",
    "alt_name": "alt_name", "dc_name": "dc_name", "user_sid": "user_sid",
    "vector": "vector", "new_password": "new_password",
    "target_dn": "target_dn", "target_obj": "target_obj",
    "out_dir": "out_dir", "save_list": "save_list",
    "filter_flag": "filter_flag", "enabled_only": "enabled_only",
    "privileged_only": "privileged_only", "os_filter": "os_filter",
    "undeleg": "undeleg", "action": "action", "source_user": "source_user",
    "save_key": "save_key", "mode": "mode",
    "relay_target_user": "relay_target_user",
    "continue_on_lockout": "continue_on_lockout",
    "command": "command", "query": "query", "attacker_ip": "attacker_ip",
    "path": "path", "param": "param", "listener": "listener",
    "client_id": "client_id", "max_depth": "max_depth", "max_pages": "max_pages",
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
        console.print(f"[yellow]{T('script_not_found', name='*', proto=protocol)}[/yellow]")
        return

    families = {}
    for meta in registry.values():
        families.setdefault(meta["family"], []).append(meta)

    tree = Tree(f"[bold {color}]{protocol.upper()}[/bold {color}]")
    for fam in sorted(families):
        branch = tree.add(f"[bold {color}]{fam}[/bold {color}]")
        for meta in sorted(families[fam], key=lambda m: m["name"]):
            from rich.text import Text
            label = Text()
            label.append(meta["name"], style="bold white")
            label.append("  ")
            label.append(meta["description"][:72], style="dim")
            branch.add(label)
    console.print(tree)
    console.print()
    console.print(f"  [dim]--script=<{T('col_type').lower()}>             {T('usage_script')}[/dim]")
    console.print(f"  [dim]--script-fam=<familia>        {T('usage_fam')}[/dim]")
    console.print(f"  [dim]--interactive-shell            {T('usage_shell')}[/dim]")
    console.print(f"  [dim]--scanner                      {T('usage_scanner')}[/dim]")
    console.print()


# ── mostrar parametros ────────────────────────────────────────────────────────

def _show_params(protocol, script_name, sp_meta, param_labels, color, args):
    req  = sp_meta.get("required", [])
    opt  = sp_meta.get("optional", [])
    defs = sp_meta.get("defaults", {})

    missing_req = [p for p in req if not _get_param_value(p, args)]

    console.print()
    console.print(Panel(
        f"[bold white]{script_name.upper()}[/bold white]"
        f"  [dim]— [bold {color}]{protocol.upper()}[/bold {color}] / {sp_meta.get('family', '')}[/dim]\n\n"
        f"{sp_meta.get('description', '')}",
        title=f"[bold {color}]{T('script_selected')}[/bold {color}]",
        border_style=color, expand=False,
    ))

    if req:
        console.print(f"[bold]{T('required_params')}[/bold]\n")
        for p in req:
            label   = param_labels.get(p, TLabel(p))
            default = defs.get(p, "")
            val     = _get_param_value(p, args)
            given   = val is not None and val != "" and val is not False
            flag    = f"--{p.replace('_', '-')}" if len(p) > 1 else f"-{p}"
            if given:
                console.print(
                    f"  [bold green]✓[/bold green]  {flag} [cyan]{val}[/cyan]"
                    + (f"  [dim]({T('default_label')}: {default})[/dim]" if default not in (None, "") else "")
                    + f"  [dim]({label})[/dim]"
                )
            else:
                console.print(
                    f"  [bold red]*[/bold red]  {flag} <valor>"
                    + (f"  [dim]({T('default_label')}: {default})[/dim]" if default not in (None, "") else "")
                    + f"  [dim]({label})[/dim]"
                )
        console.print()

    if opt:
        console.print(f"[bold]{T('optional_params')}[/bold]\n")
        for p in opt:
            label   = param_labels.get(p, TLabel(p))
            default = defs.get(p, "")
            val     = _get_param_value(p, args)
            given   = val is not None and val != "" and val is not False
            flag    = f"--{p.replace('_', '-')}"
            if given:
                console.print(
                    f"  [bold green]✓[/bold green]  {flag} [cyan]{val}[/cyan]"
                    + (f"  [dim]({T('default_label')}: {default})[/dim]" if default not in (None, "") else "")
                    + f"  [dim]({label})[/dim]"
                )
            else:
                console.print(
                    f"  [dim]·[/dim]  {flag} <valor>"
                    + (f"  [dim]({T('default_label')}: {default})[/dim]" if default not in (None, "") else "")
                    + f"  [dim]({label})[/dim]"
                )
        console.print()

    for group in sp_meta.get("mutually_exclusive", []):
        console.print(
            f"  [yellow]⚠[/yellow]  [dim]{' y '.join(group)} {T('mutually_exclusive')}[/dim]"
        )

    console.print(f"[bold]{T('usage_example')}[/bold]\n")
    example_req = " ".join(
        f"--{p.replace('_', '-')} <{p}>" for p in req
    )
    console.print(
        f"  [dim]python3 lobera.py {protocol}"
        f" --script={script_name}"
        + (f" {example_req}" if example_req else "")
        + "[/dim]"
    )
    console.print()

    if missing_req:
        console.print(
            f"[red]{T('missing_params')}:[/red] "
            + ", ".join(f"[bold]--{p.replace('_', '-')}[/bold]" for p in missing_req)
        )
        console.print(f"[dim]{T('add_and_retry')}[/dim]\n")

    return missing_req


# ── run_script ────────────────────────────────────────────────────────────────

def run_script(protocol, script_name, root_path, color="white", args=None):
    registry                   = _build_registry(protocol, root_path)
    shell_params, param_labels = _load_shell_params(protocol, root_path)

    meta_disc = (
        registry.get(script_name)
        or registry.get(script_name.replace("-", "_"))
    )
    if not meta_disc:
        console.print(
            f"[red]{T('script_not_found', name=script_name, proto=protocol)}[/red]"
        )
        console.print(f"  [dim]{T('see_list', proto=protocol)}[/dim]")
        return

    sp_meta = dict(shell_params.get(script_name, {}))
    sp_meta["family"]      = meta_disc["family"]
    sp_meta["description"] = sp_meta.get("description") or meta_disc["description"]

    if args is None:
        import argparse
        args = argparse.Namespace()

    missing = _show_params(protocol, script_name, sp_meta, param_labels, color, args)

    if missing:
        return

    target, creds = _build_target_creds(args)
    kwargs        = _cast_extra_kwargs(sp_meta, args)

    cls = _import_cls(meta_disc["path"], root_path)
    if cls is None:
        console.print(f"[red]{T('script_load_error')}[/red]")
        return

    console.rule(f"[bold {color}]{T('running')} {script_name}[/bold {color}]")
    try:
        cls(target, creds).run(**kwargs)
    except KeyboardInterrupt:
        console.print(f"\n[dim]{T('script_interrupted')}[/dim]")
    except Exception as e:
        console.print(f"[red]{T('script_error')}: {e}[/red]")
    console.rule(f"[bold {color}]{T('done')} {script_name}[/bold {color}]")
    console.print()


# ── run_script_family ─────────────────────────────────────────────────────────

def run_script_family(protocol, family, root_path, color="white", args=None):
    registry                   = _build_registry(protocol, root_path)
    shell_params, param_labels = _load_shell_params(protocol, root_path)

    scripts_in_fam = [m for m in registry.values() if m["family"] == family]
    if not scripts_in_fam:
        available = sorted({m["family"] for m in registry.values()})
        console.print(
            f"[red]{T('family_not_found', fam=family, proto=protocol)}[/red]"
        )
        console.print(f"  {T('families_available')}: {', '.join(available)}")
        return

    console.print()
    console.print(Panel(
        f"[bold white]{T('family_selected').upper()}: {family.upper()}[/bold white]"
        f"  [dim]— [bold {color}]{protocol.upper()}[/bold {color}][/dim]\n\n"
        + "\n".join(
            f"  • {m['name']}"
            for m in sorted(scripts_in_fam, key=lambda m: m["name"])
        ),
        title=f"[bold {color}]{T('running_family')}[/bold {color}]",
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
                f"[yellow]{m['name']} — {T('omitted_missing')}: {', '.join(missing)}[/yellow]"
            )
            continue

        kwargs = _cast_extra_kwargs(sp_meta, args)
        cls    = _import_cls(m["path"], root_path)
        if cls is None:
            console.print(f"[yellow]{m['name']} — {T('omitted_load')}[/yellow]")
            continue

        console.rule(f"[bold {color}]{T('running')} {m['name']}[/bold {color}]")
        try:
            cls(target, creds).run(**kwargs)
        except KeyboardInterrupt:
            console.print(f"\n[dim]{T('script_interrupted')}[/dim]")
        except Exception as e:
            console.print(f"[red]{T('script_error')} '{m['name']}': {e}[/red]")
        console.print()

    console.rule(
        f"[bold {color}]{T('family_done', fam=family)}[/bold {color}]"
    )
    console.print()
