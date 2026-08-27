# scripts/loader.py

import os
import importlib
import inspect

from scripts.base import BaseScript

_SCRIPTS_PACKAGE = "scripts"
_SCRIPTS_DIR = os.path.dirname(__file__)


def _iter_protocol_dirs():
    if not os.path.isdir(_SCRIPTS_DIR):
        return
    for entry in sorted(os.listdir(_SCRIPTS_DIR)):
        path = os.path.join(_SCRIPTS_DIR, entry)
        if os.path.isdir(path) and not entry.startswith("_"):
            yield entry, path


def discover_scripts(protocol=None):
    """
    Escanea scripts/<protocolo>/<familia>/*.py, importa cada módulo y
    recoge las clases que heredan de BaseScript y tienen 'name' definido.
    A cada clase se le asignan 'protocol' y 'category' según las dos
    carpetas que la contienen (la carpeta manda, no lo que declare el script).

    protocol=None  -> escanea TODOS los protocolos.
    protocol="smb" -> escanea solo scripts/smb/.

    Un script roto (error de import) se salta con un aviso, sin tumbar
    el descubrimiento del resto.

    Devuelve: dict {script_name: script_class}
    """
    registry = {}

    for proto_name, proto_path in _iter_protocol_dirs():
        if protocol and proto_name != protocol:
            continue

        for cat_entry in sorted(os.listdir(proto_path)):
            cat_path = os.path.join(proto_path, cat_entry)
            if not os.path.isdir(cat_path) or cat_entry.startswith("_"):
                continue

            category = cat_entry

            for fname in sorted(os.listdir(cat_path)):
                if not fname.endswith(".py") or fname.startswith("_"):
                    continue

                module_name = f"{_SCRIPTS_PACKAGE}.{proto_name}.{category}.{fname[:-3]}"
                try:
                    module = importlib.import_module(module_name)
                except Exception as e:
                    print(f"[!] No se pudo cargar el script '{module_name}': {e}")
                    continue

                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if obj is BaseScript or not issubclass(obj, BaseScript):
                        continue
                    if not getattr(obj, "name", None):
                        continue
                    if obj.__module__ != module_name:
                        continue  # evita registrar clases importadas indirectamente

                    obj.protocol = proto_name
                    obj.category = category
                    registry[obj.name] = obj

    return registry


def get_protocols():
    """Protocolos (carpetas scripts/<protocolo>/) que tienen al menos un script."""
    registry = discover_scripts()
    return sorted({cls.protocol for cls in registry.values()})


def get_categories(protocol):
    """Familias (subcarpetas) de un protocolo concreto que tienen al menos un script."""
    registry = discover_scripts(protocol=protocol)
    return sorted({cls.category for cls in registry.values()})


def get_by_category(protocol, category):
    """Devuelve {name: class} de los scripts de una familia concreta dentro de un protocolo."""
    registry = discover_scripts(protocol=protocol)
    return {name: cls for name, cls in registry.items() if cls.category == category}


def get_tree(protocol):
    """
    Devuelve {familia: [(name, description), ...]} para un protocolo,
    ordenado, listo para imprimir como árbol (ver print_protocol_tree en lobera.py).
    """
    registry = discover_scripts(protocol=protocol)
    tree = {}
    for name, cls in sorted(registry.items()):
        tree.setdefault(cls.category, []).append((name, cls.description))
    return dict(sorted(tree.items()))
