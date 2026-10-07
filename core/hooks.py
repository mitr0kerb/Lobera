# core/hooks.py
"""
Hooks entre módulos de lobera.

Implementa los flags cruzados que conectan binarios entre sí:
  --on-hash-crack  → cuando un módulo captura un hash, lanza lobera-crack automáticamente
  --try-exploit    → cuando lobera-check encuentra una vuln explotable, lanza lobera-exploit

Cada módulo puede llamar a estos hooks pasando los datos necesarios.
El hook decide si ejecutar la acción según los flags activos.
"""

import os
import sys
import subprocess

from core.output import console

# Ruta al directorio bin/ (junto a este módulo en el repo)
_BIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bin')


def _bin(nombre):
    """Devuelve la ruta absoluta a un binario en bin/."""
    return os.path.join(_BIN_DIR, nombre)


# ──────────────────────────────────────────────────────────────────────────────
# Hook: hash capturado → crackear automáticamente
# ──────────────────────────────────────────────────────────────────────────────

def on_hash_capturado(hash_str, formato, wordlist, engine='auto', rules=None,
                      target_ip=None, usuario=None, fuente=None):
    """
    Llamar cuando un módulo captura un hash (NTLM, NetNTLMv2, AS-REP, TGS...).

    Guarda el hash en la BD y, si wordlist está definida, lanza lobera-crack
    en background para intentar crackearlo.

    Parámetros:
      hash_str   — el hash capturado (string completo, en el formato del protocolo)
      formato    — 'ntlm' | 'netntlmv1' | 'netntlmv2' | 'krb5asrep' | 'krb5tgs'
      wordlist   — ruta a la wordlist para crackear, o None para solo guardar
      engine     — 'auto' | 'hashcat' | 'cpu'
      rules      — ruta a fichero de reglas hashcat (opcional)
      target_ip  — IP del objetivo (para la BD)
      usuario    — usuario al que pertenece el hash
      fuente     — texto libre (ej. 'smb-relay', 'responder', 'sam-dump')

    Devuelve el id de fila en la tabla hashes.
    """
    from core.session_db import save_hash
    hash_id = save_hash(hash_str, formato, target_ip=target_ip,
                        usuario=usuario, fuente=fuente)
    console.print(f"  [dim][hook] Hash guardado en BD (id={hash_id}, formato={formato})[/dim]")

    if not wordlist:
        return hash_id

    # Lanzar lobera-crack en background
    cmd = [sys.executable, _bin('lobera-crack'),
           '-H', hash_str,
           '-w', wordlist,
           '--engine', engine]
    if rules:
        cmd += ['-r', rules]

    console.print(f"  [dim][hook] Lanzando lobera-crack en background...[/dim]")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        # Esperar resultado (el crack suele ser rápido para NTLM con GPU)
        stdout, _ = proc.communicate(timeout=300)
        if proc.returncode == 0:
            # Buscar la contraseña en la salida
            password = _extraer_password_de_salida(stdout)
            if password:
                from core.session_db import mark_hash_crackeado
                mark_hash_crackeado(hash_id, password)
                console.print(f"  [green][hook] Hash crackeado:[/green] [bold]{password}[/bold]")
            else:
                console.print("  [yellow][hook] Hash no crackeado con la wordlist dada.[/yellow]")
        else:
            console.print("  [yellow][hook] lobera-crack terminó sin resultado.[/yellow]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow][hook] Timeout crackeando hash — continúa en background.[/yellow]")
        proc.kill()
    except Exception as e:
        console.print(f"  [dim][hook] Error lanzando lobera-crack: {e}[/dim]")

    return hash_id


def _extraer_password_de_salida(salida):
    """
    Parsea la salida de lobera-crack buscando la contraseña encontrada.
    Busca líneas del tipo: "Contraseña encontrada: <password>"
    """
    for linea in salida.splitlines():
        linea = linea.strip()
        if 'Contraseña encontrada:' in linea:
            partes = linea.split('Contraseña encontrada:', 1)
            if len(partes) == 2:
                return partes[1].strip()
        # Formato potfile hashcat: hash:password
        if ':' in linea and not linea.startswith('$') and not linea.startswith('::'):
            partes = linea.rsplit(':', 1)
            if len(partes) == 2 and partes[1]:
                return partes[1]
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Hook: vuln encontrada → explotar automáticamente
# ──────────────────────────────────────────────────────────────────────────────

def on_vuln_encontrada(target_ip, vuln_id, descripcion, port=None, protocol=None,
                       try_exploit=False, exploit_opts=None):
    """
    Llamar cuando lobera-check detecta una vulnerabilidad.

    Guarda la vuln en la BD. Si try_exploit=True, lanza lobera-exploit
    automáticamente.

    Parámetros:
      target_ip    — IP del objetivo vulnerable
      vuln_id      — identificador del CVE / vuln (ej. 'MS17-010')
      descripcion  — texto descriptivo
      port         — puerto afectado
      protocol     — protocolo (ej. 'smb', 'rdp')
      try_exploit  — si True, lanza lobera-exploit inmediatamente
      exploit_opts — dict con opciones adicionales para el exploit
                     (ej. {'lhost': '10.0.0.1', 'lport': 4444})

    Devuelve el id de fila en la tabla vulns.
    """
    from core.session_db import save_vuln
    explotable = vuln_id in EXPLOTABLES
    vuln_row_id = save_vuln(target_ip, vuln_id, descripcion,
                            port=port, protocol=protocol, explotable=explotable)
    console.print(f"  [dim][hook] Vuln guardada en BD (id={vuln_row_id}, vuln={vuln_id})[/dim]")

    if not try_exploit or not explotable:
        if try_exploit and not explotable:
            console.print(f"  [yellow][hook] No hay exploit disponible para {vuln_id}.[/yellow]")
        return vuln_row_id

    # Lanzar lobera-exploit
    console.print(f"  [cyan][hook] Lanzando lobera-exploit para {vuln_id} → {target_ip}[/cyan]")
    opts = exploit_opts or {}
    cmd = [sys.executable, _bin('lobera-exploit'),
           '--target', target_ip,
           '--vuln', vuln_id]
    if port:
        cmd += ['--port', str(port)]
    for k, v in opts.items():
        cmd += [f'--{k}', str(v)]

    try:
        subprocess.run(cmd, check=False)
    except Exception as e:
        console.print(f"  [red][hook] Error lanzando lobera-exploit: {e}[/red]")

    return vuln_row_id


# ──────────────────────────────────────────────────────────────────────────────
# Registro de vulns explotables conocidas (las que lobera-exploit soporta)
# ──────────────────────────────────────────────────────────────────────────────

# Importamos aquí para evitar import circular: session_db no importa hooks
# pero hooks sí puede importar session_db tras la inicialización.
# La lista de vulns explotables la mantenemos aquí para que hooks.py
# sea la única fuente de verdad.

EXPLOTABLES = {
    'MS17-010',   # EternalBlue — SMB
    'MS08-067',   # NetAPI — SMB legacy
}


def add_args_on_hash_crack(parser):
    """
    Añade --on-hash-crack y sus dependencias a un argparse.ArgumentParser.
    Llamar desde el main() de cualquier módulo que pueda capturar hashes.
    """
    grp = parser.add_argument_group('hooks automáticos')
    grp.add_argument('--on-hash-crack', metavar='WORDLIST',
                     help='Si se captura un hash, crackearlo automáticamente con esta wordlist')
    grp.add_argument('--crack-engine', choices=['auto', 'hashcat', 'cpu'], default='auto',
                     help='Motor para --on-hash-crack (default: auto)')
    grp.add_argument('--crack-rules', metavar='FICHERO',
                     help='Reglas hashcat para --on-hash-crack')
    return grp


def add_args_try_exploit(parser):
    """
    Añade --try-exploit a un argparse.ArgumentParser.
    --lhost y --lport se omiten si el parser ya los tiene definidos.
    Llamar desde el main() de lobera-check.
    """
    grp = parser.add_argument_group('explotación automática')
    grp.add_argument('--try-exploit', action='store_true',
                     help='Si se detecta una vuln explotable, intentar explotarla automáticamente')
    # Solo añadir lhost/lport si el parser aún no los tiene
    opciones_existentes = {a.option_strings[0] for a in parser._actions if a.option_strings}
    if '--lhost' not in opciones_existentes:
        grp.add_argument('--lhost', metavar='IP',
                         help='IP del listener para shells inversas (con --try-exploit)')
    if '--lport' not in opciones_existentes:
        grp.add_argument('--lport', metavar='PUERTO', type=int, default=4444,
                         help='Puerto del listener (default: 4444)')
    return grp
