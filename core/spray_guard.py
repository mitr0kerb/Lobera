# core/spray_guard.py
"""
Utilidades de seguridad para ataques de password spray.

Funciones exportadas:
  check_lockout_policy(target, creds) → dict con threshold, duration, delay_recomendado
  safe_delay(policy)                  → segundos recomendados de espera entre intentos
  warn_if_risky(policy)               → imprime aviso si el threshold es bajo

El objetivo es evitar bloqueos accidentales durante un spray.
"""

from core.output import print_result, print_check, console


def check_lockout_policy(target, creds):
    """
    Intenta obtener la política de lockout del dominio vía SAMR/RPC.
    Devuelve un dict:
        {
          "threshold":  int | None,   # 0 = sin lockout
          "duration":   int | None,   # minutos
          "window":     int | None,   # ventana de observación en minutos
          "source":     str,          # "rpc" | "unavailable"
        }
    Si no se puede obtener, devuelve todo None y source="unavailable".
    """
    result = {"threshold": None, "duration": None, "window": None, "source": "unavailable"}

    try:
        from modules.rpc import RPCModule
        rpc = RPCModule(target, creds)
        if not rpc.connect():
            return result

        try:
            info = rpc.get_domain_info()
            result["threshold"] = info.get("lockout_threshold")
            result["duration"]  = info.get("lockout_duration")
            result["source"]    = "rpc"
        except Exception:
            pass
        finally:
            rpc.disconnect()
    except ImportError:
        pass

    return result


def safe_delay(policy):
    """
    Calcula el delay recomendado en segundos entre intentos de spray
    basándose en la política de lockout.

    Lógica:
      - threshold=0 → sin lockout → 0s (spray libre)
      - threshold=1 → cualquier intento bloquea → abortar (retorna -1)
      - threshold≤3 → delay agresivo: 60s para estar muy por debajo de la ventana
      - threshold≤10 → delay moderado: 30s
      - threshold>10 → delay mínimo: 5s (por si acaso)
      - threshold=None → no se sabe → delay conservador: 30s
    """
    t = policy.get("threshold")

    if t is None:
        return 30.0   # desconocido → conservador

    if t == 0:
        return 0.0    # sin política de lockout

    if t == 1:
        return -1     # cualquier intento bloquearía — señal de abortar

    if t <= 3:
        return 60.0

    if t <= 10:
        return 30.0

    return 5.0


def warn_if_risky(policy, requested_delay=None, continue_on_lockout=False):
    """
    Imprime avisos si la política de lockout es restrictiva.
    Devuelve True si el spray puede continuar, False si debe abortarse.
    """
    t         = policy.get("threshold")
    duration  = policy.get("duration")
    source    = policy.get("source")

    if source == "unavailable":
        print_check(
            "No se pudo obtener política de lockout — delay recomendado: 30s",
            ok=False,
        )
        return True

    if t is None:
        print_check("Lockout threshold desconocido — procede con cautela", ok=False)
        return True

    if t == 0:
        print_check("lockout_threshold=0 → spray sin riesgo de bloqueo", ok=True)
        return True

    if t == 1:
        msg = "lockout_threshold=1 → cualquier intento bloquea la cuenta"
        if continue_on_lockout:
            console.print(f"  [bold red]⚠  {msg}[/bold red]")
            console.print("  [yellow]--continue-on-lockout activo: proceeding at your own risk[/yellow]")
            return True
        else:
            print_check(f"{msg} — spray abortado (usa --continue-on-lockout para forzar)", ok=False)
            return False

    # threshold entre 2 y N
    rec = safe_delay(policy)
    dur_str = f"{duration} min" if duration else "desconocida"
    print_check(
        f"lockout_threshold={t} · duración={dur_str} · delay recomendado: {rec:.0f}s",
        ok=(rec == 0),
    )

    if requested_delay is not None and requested_delay < rec and t <= 5:
        msg = (
            f"delay={requested_delay}s es menor que el recomendado ({rec:.0f}s) "
            f"para threshold={t}"
        )
        if continue_on_lockout:
            console.print(f"  [yellow]⚠  {msg} — continuando (--continue-on-lockout)[/yellow]")
        else:
            print_check(f"{msg} — ajusta --delay o usa --continue-on-lockout", ok=False)
            return False

    return True
