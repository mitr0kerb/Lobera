# core/cidr.py
"""
Expansión de objetivos: CIDR, rangos y listas de fichero.

expand_targets(target_str) → list[str]
    Acepta:
      - IP única:          "10.10.10.5"
      - CIDR:              "10.10.10.0/24"
      - Rango:             "10.10.10.1-10.10.10.20"  o  "10.10.10.1-20"
      - Fichero:           "@targets.txt" (una IP/CIDR por línea, # = comentario)
      - Coma separado:     "10.10.10.1,10.10.10.2,10.10.10.0/24"
"""

import ipaddress
import os


def _expand_one(entry: str) -> list[str]:
    """Expande una entrada individual (IP, CIDR o rango)."""
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return []

    # CIDR
    if "/" in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            return [str(h) for h in net.hosts()]
        except ValueError:
            return [entry]

    # Rango: "10.10.10.1-10.10.10.20" o "10.10.10.1-20"
    if "-" in entry:
        parts = entry.split("-", 1)
        start_str = parts[0].strip()
        end_str   = parts[1].strip()
        try:
            start = ipaddress.ip_address(start_str)
            # Si el final es solo la última octet (corto)
            if "." not in end_str:
                base = ".".join(start_str.split(".")[:-1])
                end  = ipaddress.ip_address(f"{base}.{end_str}")
            else:
                end  = ipaddress.ip_address(end_str)
            if int(end) < int(start):
                return [entry]
            return [str(ipaddress.ip_address(i))
                    for i in range(int(start), int(end) + 1)]
        except ValueError:
            return [entry]

    return [entry]


def expand_targets(target_str: str | None) -> list[str]:
    """
    Expande target_str a una lista plana de IPs/hostnames.
    Devuelve lista vacía si target_str es None.
    """
    if not target_str:
        return []

    result = []

    # Fichero de objetivos: @ruta
    if target_str.startswith("@"):
        path = target_str[1:]
        if not os.path.isfile(path):
            from core.output import console
            console.print(f"[red]Fichero de objetivos no encontrado: {path}[/red]")
            return []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for sub in line.split(","):
                    result.extend(_expand_one(sub))
        return result

    # Coma separado
    for part in target_str.split(","):
        result.extend(_expand_one(part))

    return result
