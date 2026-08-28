# scripts/loader.py

import os
import importlib
import inspect
import traceback

from scripts.base import BaseScript
from core.output import console   # ← consistencia con el resto del proyecto

_SCRIPTS_PACKAGE = "scripts"
_SCRIPTS_DIR = os.path.dirname(__file__)

# ─── Caché de módulo ────────────────────────────────────────────────────────
# discover_scripts() se invoca desde get_tree(), get_by_category(), etc. —
# potencialmente varias veces por invocación de Lobera. Sin caché, cada llamada
# reimporta N módulos del disco. Con la caché, la primera llamada paga el coste
# de importación; las siguientes son un lookup de dict.
#
# La caché se invalida si se llama a _clear_cache() (útil en tests unitarios).
# En producción nunca hay necesidad de invalidarla: los scripts no cambian
# mientras la herramienta está corriendo.
#
# Clave: protocol | None (None = todos los protocolos)
# Valor: dict {script_name: script_class}
_cache: dict[str | None, dict] = {}


def _clear_cache():
    """Limpia la caché de scripts — solo para tests."""
    _cache.clear()


def _iter_protocol_dirs():
    if not os.path.isdir(_SCRIPTS_DIR):
        return
    for entry in sorted(os.listdir(_SCRIPTS_DIR)):
        path = os.path.join(_SCRIPTS_DIR, entry)
        if os.path.isdir(path) and not entry.startswith("_"):
            yield entry, path


def discover_scripts(protocol: str | None = None) -> dict:
    """
    Escanea scripts/<protocolo>/<familia>/*.py, importa cada módulo y
    recoge las clases que heredan de BaseScript y tienen 'name' definido.

    protocol=None  → escanea TODOS los protocolos (resultado cacheado aparte).
    protocol="smb" → escanea solo scripts/smb/ (resultado cacheado por protocolo).

    Registro: la clave es OBJ.NAME (ej. "shares", "user-enum").
    Las colisiones entre protocolos distintos se evitan porque todas las
    funciones públicas (get_tree, get_by_category…) filtran POR PROTOCOLO
    antes de devolver resultados, y discover_scripts(protocol=X) solo
    incluye scripts del protocolo X. La clave global sin protocolo es solo
    para get_protocols(), que solo lee .protocol de los valores.

    Un script roto (error de import) se muestra con console.print y se salta,
    sin tumbar el descubrimiento del resto.
    """
    cache_key = protocol  # None o "smb", "kerberos", etc.
    if cache_key in _cache:
        return _cache[cache_key]

    registry: dict = {}
    import_errors: list[tuple[str, Exception]] = []

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

                module_name = (
                    f"{_SCRIPTS_PACKAGE}.{proto_name}.{category}.{fname[:-3]}"
                )
                try:
                    module = importlib.import_module(module_name)
                except Exception as exc:
                    # Mostrar con console.print (no print() plano) para
                    # coherencia visual, y guardar para un posible resumen.
                    console.print(
                        f"[yellow][!] No se pudo cargar '{module_name}': "
                        f"{exc}[/yellow]"
                    )
                    import_errors.append((module_name, exc))
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

    _cache[cache_key] = registry
    return registry


def get_protocols() -> list[str]:
    """Protocolos con al menos un script cargado."""
    registry = discover_scripts()          # None → todos
    return sorted({cls.protocol for cls in registry.values()})


def get_categories(protocol: str) -> list[str]:
    """Familias de un protocolo concreto con al menos un script."""
    registry = discover_scripts(protocol=protocol)
    return sorted({cls.category for cls in registry.values()})


def get_by_category(protocol: str, category: str) -> dict:
    """Devuelve {name: class} de los scripts de una familia dentro de un protocolo."""
    registry = discover_scripts(protocol=protocol)
    return {
        name: cls for name, cls in registry.items()
        if cls.category == category
    }


def get_tree(protocol: str) -> dict:
    """
    Devuelve {familia: [(name, description), ...]} listo para imprimir como árbol.
    """
    registry = discover_scripts(protocol=protocol)
    tree: dict = {}
    for name, cls in sorted(registry.items()):
        tree.setdefault(cls.category, []).append((name, cls.description))
    return dict(sorted(tree.items()))
