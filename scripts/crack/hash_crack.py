# scripts/crack/hash_crack.py
"""
Script de crackeo offline de hashes Kerberos y NTLM.

Llama al binario Rust `lobera-crack` mediante subprocess y parsea su output JSON.

Formatos soportados:
  asrep   — $krb5asrep$23$...   (ASREPRoasting, hashcat 18200)
  tgs     — $krb5tgs$23$*...*   (Kerberoasting, hashcat 13100)
  ntlm    — <32 hex chars>       (NT hash)
  ntlmv2  — $NETNTLMv2$...      (capturas Responder, hashcat 5600)
  auto    — detección automática

Uso desde lobera.py:
  python lobera.py crack -f asrep -H '$krb5asrep$23$...' -w rockyou.txt
  python lobera.py crack -f auto  -H hashes.txt           -w rockyou.txt -t 8
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from core.output import print_result, console
from core import session_db


def _find_binary() -> str:
    """Busca lobera-crack en bin/ relativo al proyecto o en PATH."""
    # Relativo a este archivo: scripts/crack/ → ../../bin/
    candidate = Path(__file__).resolve().parent.parent.parent / "bin" / "lobera-crack"
    if candidate.exists():
        return str(candidate)
    found = shutil.which("lobera-crack")
    if found:
        return found
    raise FileNotFoundError(
        "Binario 'lobera-crack' no encontrado. "
        "Compila con: cd src/cracker && cargo build --release && cp target/release/lobera-crack ../../bin/"
    )


class Script:
    """
    Wrapper Python sobre el cracker Rust lobera-crack.
    Parsea el output JSON y guarda los resultados en session_db.
    """

    NAME = "crack"
    DESCRIPTION = "Crackeo offline de hashes Kerberos/NTLM (Rust, multi-core)"

    def __init__(self, target, creds):
        self.target = target
        self.creds  = creds

    def run(self, args):
        """
        args esperados (de argparse):
          args.format   — asrep|tgs|ntlm|ntlmv2|auto
          args.hash     — hash directo o path a fichero de hashes
          args.wordlist — path a diccionario (rockyou.txt, etc.)
          args.threads  — número de threads (defecto: CPUs)
          args.progress — mostrar progreso cada N contraseñas
          args.json_only— suprimir todo excepto JSON
        """
        binary = _find_binary()
        cmd = [binary, "-f", args.format, "-H", args.hash, "-w", args.wordlist]

        if hasattr(args, "threads") and args.threads:
            cmd += ["-t", str(args.threads)]
        if hasattr(args, "progress") and args.progress:
            cmd += ["--progress", str(args.progress)]
        if getattr(args, "json_only", False):
            cmd += ["--json-only"]

        console.print(f"  [cyan]lobera-crack[/cyan] {' '.join(cmd[1:])}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            console.print(f"  [red]Error: binario no encontrado: {binary}[/red]")
            return

        # Progreso/errores del cracker van a stderr — los mostramos en tiempo real
        if proc.stderr:
            for line in proc.stderr.strip().splitlines():
                console.print(f"  [dim]{line}[/dim]")

        if not proc.stdout.strip():
            console.print("  [yellow]Sin output JSON del cracker.[/yellow]")
            return

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            console.print(f"  [red]JSON inválido: {e}[/red]")
            console.print(proc.stdout[:500])
            return

        cracked   = data.get("cracked", [])
        failed    = data.get("failed", [])
        stats     = data.get("stats", {})

        # ── Mostrar resultados ─────────────────────────────────────────────────
        if cracked:
            console.print(f"\n  [bold green]✓ {len(cracked)} hash(es) crackeados[/bold green]")
            for item in cracked:
                h = item.get("hash", "")[:40] + ("..." if len(item.get("hash","")) > 40 else "")
                pw = item.get("password", "")
                console.print(f"    [green]{h}[/green]  →  [bold]{pw}[/bold]")
                print_result("crack", {
                    "hash":     item.get("hash"),
                    "password": pw,
                    "format":   item.get("format"),
                })
                # Guardar en session_db
                try:
                    session_db.save_finding(
                        category="cracked_hash",
                        data={
                            "hash":     item.get("hash"),
                            "password": pw,
                            "format":   item.get("format"),
                            "wordlist": args.wordlist,
                        },
                    )
                except Exception:
                    pass
        else:
            console.print("  [yellow]No se crackeó ningún hash.[/yellow]")

        if failed:
            console.print(f"  [dim]{len(failed)} hash(es) sin crackear[/dim]")

        if stats:
            tried    = stats.get("tried", 0)
            elapsed  = stats.get("elapsed_secs", 0)
            speed    = stats.get("per_second", 0)
            console.print(
                f"  [dim]Probadas {tried:,} contraseñas en {elapsed:.1f}s "
                f"({speed:,.0f}/s)[/dim]"
            )

        # ── Sugerencias de siguiente paso ──────────────────────────────────────
        if cracked:
            self._suggest_next(cracked)

    def _suggest_next(self, cracked: list):
        """Sugiere comandos de Lobera basados en los hashes crackeados."""
        fmt = cracked[0].get("format", "")
        console.print("\n  [bold]Siguiente paso sugerido:[/bold]")
        if fmt in ("asrep", "tgs"):
            console.print(
                "    [cyan]python lobera.py smb -t <DC> -u <usuario> -p <password crackeada>[/cyan]"
            )
            console.print(
                "    [cyan]python lobera.py kerberos tgt -t <DC> -u <usuario> -p <password>[/cyan]"
            )
        elif fmt == "ntlm":
            console.print(
                "    [cyan]python lobera.py smb -t <DC> --nt <hash>  # Pass-the-Hash[/cyan]"
            )
        elif fmt == "ntlmv2":
            console.print(
                "    [cyan]python lobera.py smb -t <DC> -u <usuario> -p <password crackeada>[/cyan]"
            )
